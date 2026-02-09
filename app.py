#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
家庭网络端口管理器 - Home Port Manager
一键扫描、可视化、管理内网设备端口

使用方法:
    python app.py
    
然后浏览器访问: http://127.0.0.1:5000
"""

import os
import sys
import json
import socket
import threading
import subprocess
import re
import time
import importlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def install_package(package_name, import_name=None):
    """自动安装缺失的包"""
    if import_name is None:
        import_name = package_name
    try:
        importlib.import_module(import_name)
        return True
    except ImportError:
        print(f"[安装] 正在安装 {package_name}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package_name, "-q"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[安装] {package_name} 安装成功")
            return True
        except Exception as e:
            print(f"[安装] {package_name} 安装失败: {e}")
            return False

def check_and_install_dependencies():
    """检查并安装所有依赖"""
    print("[检查] 正在检查依赖...")
    
    deps = [
        ("flask", "flask"),
        ("netifaces-plus", "netifaces"),
    ]
    
    all_installed = True
    for package, import_name in deps:
        if not install_package(package, import_name):
            all_installed = False
    
    if not all_installed:
        print("[错误] 部分必要依赖安装失败，请手动运行: pip install flask netifaces-plus")
        input("按回车键退出...")
        sys.exit(1)
    
    print("[OK] 依赖检查完成")

check_and_install_dependencies()

try:
    from flask import Flask, jsonify, request, Response
    import netifaces
except ImportError as e:
    print(f"[错误] 导入失败: {e}")
    input("按回车键退出...")
    sys.exit(1)

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

SCAN_CACHE = {}
SCAN_STATUS = {"scanning": False, "paused": False, "progress": 0, "speed_mode": "fast", "current_device": ""}
DEVICE_NOTES = {}
SCAN_STREAM = {"current_ip": "", "found_ports": [], "completed_devices": []}

SCAN_SPEED = {
    "fast":     {"ping_workers": 254, "port_workers": 500, "timeout": 0.1, "name": "极速"},
    "standard": {"ping_workers": 50, "port_workers": 50, "timeout": 0.5, "name": "常规"}
}

COMMON_PORTS = [
    20,21,22,23,25,53,67,68,69,80,81,82,83,88,110,111,113,119,123,135,137,138,139,
    143,161,179,194,389,443,445,464,465,500,514,515,520,521,546,547,554,587,631,636,
    989,990,993,995,1080,1194,1433,1434,1521,1701,1723,1883,1900,2049,2082,2083,2086,
    2087,2095,2096,2222,2375,2376,3000,3128,3306,3389,5432,5500,5555,5601,5672,5900,
    5901,5984,6379,6443,6631,6667,7001,7474,8000,8008,8080,8086,8088,8443,8883,8888,
    9000,9042,9092,9200,9443,9999,11211,12306,27017,27018,28015,50000
]

SAVE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scan_history.json')
DEVICE_NOTES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'device_notes.json')

def load_data():
    global SCAN_CACHE, DEVICE_NOTES
    if os.path.exists(SAVE_FILE):
        try:
            with open(SAVE_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                SCAN_CACHE = {d['ip']: d for d in data.get('devices', [])}
        except:
            pass
    if os.path.exists(DEVICE_NOTES_FILE):
        try:
            with open(DEVICE_NOTES_FILE, 'r', encoding='utf-8') as f:
                DEVICE_NOTES = json.load(f)
        except:
            pass

def save_notes():
    try:
        with open(DEVICE_NOTES_FILE, 'w', encoding='utf-8') as f:
            json.dump(DEVICE_NOTES, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"保存备注失败: {e}")
        return False

load_data()

PORT_SERVICES = {
    20: ("FTP-Data", "中", "FTP数据传输"),
    21: ("FTP", "中", "文件传输协议"),
    22: ("SSH", "中", "安全远程登录"),
    23: ("Telnet", "高", "明文远程登录-极不安全"),
    25: ("SMTP", "中", "邮件发送服务"),
    53: ("DNS", "低", "域名解析服务"),
    67: ("DHCP", "低", "动态主机配置"),
    68: ("DHCP-Client", "低", "DHCP客户端"),
    69: ("TFTP", "中", "简单文件传输"),
    80: ("HTTP", "中", "网站服务-未加密"),
    88: ("Kerberos", "中", "认证服务"),
    110: ("POP3", "中", "邮件接收-未加密"),
    111: ("RPC", "中", "RPC端口映射"),
    135: ("RPC", "高", "Windows远程过程调用"),
    139: ("NetBIOS", "高", "Windows文件共享"),
    143: ("IMAP", "中", "邮件访问-未加密"),
    161: ("SNMP", "中", "网络管理协议"),
    443: ("HTTPS", "低", "安全网站服务"),
    445: ("SMB", "高", "Windows文件共享"),
    465: ("SMTPS", "低", "SMTP over SSL"),
    514: ("Syslog", "中", "系统日志"),
    515: ("LPD", "中", "打印机服务"),
    631: ("IPP", "中", "互联网打印协议"),
    636: ("LDAPS", "低", "LDAP over SSL"),
    8080: ("HTTP-Proxy", "中", "Web代理/管理后台"),
    8443: ("HTTPS-Alt", "低", "安全网站(备用)"),
    3389: ("RDP", "高", "Windows远程桌面"),
    3306: ("MySQL", "中", "MySQL数据库"),
    5432: ("PostgreSQL", "中", "PostgreSQL数据库"),
    6379: ("Redis", "高", "Redis缓存数据库"),
    27017: ("MongoDB", "高", "MongoDB数据库"),
    1883: ("MQTT", "中", "物联网消息协议"),
    8883: ("MQTTS", "低", "MQTT over SSL"),
    5900: ("VNC", "高", "远程控制"),
    5901: ("VNC-1", "高", "VNC显示:1"),
    9999: ("Web", "中", "Web管理界面"),
    10000: ("Webmin", "中", "Linux管理面板"),
    12306: ("Steam/Custom", "中", "Steam或自定义应用"),
}

class HomeNetworkScanner:
    def __init__(self):
        self.gateway = self._get_gateway()
        self.network = self._get_network()
        self.local_ip = self._get_local_ip()
        self.speed_mode = "fast"
        
    def set_speed_mode(self, mode):
        if mode in SCAN_SPEED:
            self.speed_mode = mode
            config = SCAN_SPEED[mode]
            print(f"[扫描] 速度模式: {config['name']}")
            return True
        return False
    
    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _get_gateway(self):
        try:
            gateways = netifaces.gateways()
            return gateways['default'][netifaces.AF_INET][0]
        except:
            return "192.168.1.1"
    
    def _get_network(self):
        ip = self._get_local_ip()
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    
    def _tcp_check(self, ip, port, timeout=1.0):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def scan_ports(self, ip, ports=None, progress_callback=None, found_callback=None, fast_mode=False):
        import concurrent.futures
        
        if ports is None:
            if fast_mode:
                ports = COMMON_PORTS.copy()
            else:
                ports = list(range(1, 65536))
        
        config = SCAN_SPEED.get(self.speed_mode, SCAN_SPEED["standard"])
        workers = config["port_workers"]
        timeout = config["timeout"]
        
        open_ports = []
        total = len(ports)
        scanned = [0]
        
        print(f"[扫描] {ip} 的 {total} 个端口...")
        
        def check_single_port(port):
            if SCAN_STATUS.get("paused", False):
                return None
            if self._tcp_check(ip, port, timeout=timeout):
                service = PORT_SERVICES.get(port, (f"Port {port}", "低", "未知服务"))
                return {
                    "port": port,
                    "service": service[0],
                    "risk": service[1],
                    "risk_desc": service[2],
                }
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_port = {executor.submit(check_single_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
                    if found_callback:
                        found_callback(result)
                    print(f"  [开放] {result['port']} - {result['service']}")
                
                scanned[0] += 1
                if progress_callback and scanned[0] % 500 == 0:
                    progress_callback(scanned[0], total)
        
        open_ports.sort(key=lambda x: x['port'])
        print(f"[完成] 发现 {len(open_ports)} 个开放端口")
        return open_ports
    
    def ping_scan(self):
        base_ip = '.'.join(self.network.split('.')[:3])
        found = []
        timeout_ms = 500
        workers = 100
        
        print(f"[设备发现] 扫描网段 {base_ip}.1-254 ...")
        
        def ping_host(suffix):
            while SCAN_STATUS.get("paused", False):
                time.sleep(0.5)
            
            ip = f"{base_ip}.{suffix}"
            if ip == self.local_ip:
                return None
            try:
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', str(timeout_ms), ip],
                    capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0 and 'TTL' in result.stdout.upper():
                    try:
                        arp_result = subprocess.run(
                            ['arp', '-a', ip], capture_output=True, text=True, timeout=2
                        )
                        mac_match = re.search(r'([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}', arp_result.stdout)
                        mac = mac_match.group(0) if mac_match else "00:00:00:00:00:00"
                    except:
                        mac = "00:00:00:00:00:00"
                    
                    print(f"  [发现] {ip} ({mac})")
                    return (ip, mac, "")
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(ping_host, range(1, 255)))
        
        found = [r for r in results if r is not None]
        print(f"[设备发现] 共发现 {len(found)} 个设备")
        return found
    
    def discovery(self, fast_mode=False):
        global SCAN_STATUS, SCAN_STREAM
        
        SCAN_STATUS["scanning"] = True
        SCAN_STATUS["paused"] = False
        SCAN_STATUS["progress"] = 0
        SCAN_STREAM["found_ports"] = []
        SCAN_STREAM["completed_devices"] = []
        
        found_devices = self.ping_scan()
        total_devices = len(found_devices)
        
        print(f"[扫描] 发现 {total_devices} 个设备")
        
        devices = []
        
        for idx, device_data in enumerate(found_devices):
            ip, mac, device_name = device_data
            device_percent = int((idx / total_devices) * 100)
            SCAN_STATUS["progress"] = device_percent
            SCAN_STATUS["current_device"] = ip
            SCAN_STREAM["current_ip"] = ip
            SCAN_STREAM["found_ports"] = []
            
            def port_progress(scanned, total_ports):
                pass
            
            def on_port_found(port_info):
                SCAN_STREAM["found_ports"].append(port_info)
            
            ports = self.scan_ports(ip, progress_callback=port_progress, 
                                   found_callback=on_port_found, fast_mode=fast_mode)
            
            device_info = {
                "ip": ip,
                "mac": mac,
                "name": device_name or "未知设备",
                "vendor": "未知",
                "type": "",
                "ports": ports,
                "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            devices.append(device_info)
            SCAN_STREAM["completed_devices"].append(device_info)
        
        SCAN_STATUS["progress"] = 100
        SCAN_STATUS["current_device"] = ""
        SCAN_STREAM["current_ip"] = ""
        
        try:
            save_data = {
                'timestamp': datetime.now().isoformat(),
                'devices': devices
            }
            with open(SAVE_FILE, 'w', encoding='utf-8') as f:
                json.dump(save_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[保存] 失败: {e}")
        
        SCAN_STATUS["scanning"] = False
        return devices

scanner = HomeNetworkScanner()

@app.route('/')
def index():
    return "Home Port Manager - API Server Running"

@app.route('/api/scan/devices')
def api_scan_devices():
    global SCAN_CACHE
    
    if SCAN_STATUS["scanning"]:
        return jsonify({"error": "扫描进行中"}), 400
    
    SCAN_STATUS["scanning"] = True
    SCAN_STATUS["paused"] = False
    SCAN_STATUS["progress"] = 0
    SCAN_STATUS["current_device"] = "正在发现设备..."
    
    def scan_task():
        global SCAN_CACHE
        try:
            found_devices = scanner.ping_scan()
            for ip, mac, name in found_devices:
                if ip not in SCAN_CACHE:
                    SCAN_CACHE[ip] = {
                        "ip": ip,
                        "mac": mac,
                        "vendor": "未知",
                        "type": "",
                        "ports": [],
                        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
            SCAN_STATUS["progress"] = 100
            SCAN_STATUS["scanning"] = False
        except Exception as e:
            print(f"[错误] {e}")
            SCAN_STATUS["scanning"] = False
    
    threading.Thread(target=scan_task, daemon=True).start()
    return jsonify({"status": "started"})

@app.route('/api/scan/ports/<ip>')
def api_scan_ports(ip):
    if SCAN_STATUS["scanning"]:
        return jsonify({"error": "扫描进行中"}), 400
    
    if ip not in SCAN_CACHE:
        return jsonify({"error": "设备不存在"}), 404
    
    port_mode = request.args.get('mode', 'common')
    fast_mode = (port_mode == 'common')
    
    SCAN_STATUS["scanning"] = True
    SCAN_STATUS["paused"] = False
    SCAN_STATUS["current_device"] = ip
    SCAN_STREAM["found_ports"] = []
    
    def scan_task():
        try:
            ports = scanner.scan_ports(ip, fast_mode=fast_mode)
            SCAN_CACHE[ip]["ports"] = ports
            SCAN_CACHE[ip]["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            SCAN_STATUS["scanning"] = False
        except Exception as e:
            print(f"[错误] {e}")
            SCAN_STATUS["scanning"] = False
    
    threading.Thread(target=scan_task, daemon=True).start()
    return jsonify({"status": "started"})

@app.route('/api/scan/all')
def api_scan_all():
    global SCAN_CACHE
    
    if SCAN_STATUS["scanning"]:
        return jsonify({"error": "扫描进行中"}), 400
    
    port_mode = request.args.get('mode', 'common')
    fast_mode = (port_mode == 'common')
    
    SCAN_STATUS["scanning"] = True
    
    def scan_task():
        global SCAN_CACHE
        devices = scanner.discovery(fast_mode=fast_mode)
        SCAN_CACHE = {d['ip']: d for d in devices}
        SCAN_STATUS["scanning"] = False
    
    threading.Thread(target=scan_task, daemon=True).start()
    return jsonify({"status": "started"})

@app.route('/api/status')
def api_status():
    return jsonify(SCAN_STATUS)

@app.route('/api/scan/stream')
def api_scan_stream():
    return jsonify({
        "scanning": SCAN_STATUS["scanning"],
        "paused": SCAN_STATUS.get("paused", False),
        "current_device": SCAN_STATUS.get("current_device", ""),
        "progress": SCAN_STATUS["progress"],
        "found_ports": SCAN_STREAM.get("found_ports", []),
    })

@app.route('/api/scan/pause', methods=['POST'])
def api_scan_pause():
    data = request.json or {}
    paused = data.get('paused', True)
    SCAN_STATUS["paused"] = paused
    return jsonify({"paused": paused})

@app.route('/api/devices')
def api_devices():
    devices = []
    for ip, device in SCAN_CACHE.items():
        device_copy = device.copy()
        note = DEVICE_NOTES.get(ip, {})
        device_copy['custom_name'] = note.get('name', '')
        devices.append(device_copy)
    return jsonify(devices)

@app.route('/api/device/note', methods=['POST'])
def api_device_note():
    data = request.json
    ip = data.get('ip')
    name = data.get('name', '')
    
    if not ip:
        return jsonify({'success': False})
    
    DEVICE_NOTES[ip] = {'name': name, 'note': ''}
    save_notes()
    return jsonify({'success': True})

@app.route('/api/speed', methods=['POST'])
def api_speed():
    data = request.json or {}
    mode = data.get('mode', 'standard')
    
    if mode in SCAN_SPEED:
        scanner.set_speed_mode(mode)
        return jsonify({"success": True, "message": f"已切换到{SCAN_SPEED[mode]['name']}模式"})
    return jsonify({"success": False})

@app.route('/api/export')
def api_export():
    devices = list(SCAN_CACHE.values())
    output = json.dumps({'devices': devices}, ensure_ascii=False, indent=2)
    response = Response(output, mimetype='application/json')
    response.headers['Content-Disposition'] = 'attachment; filename=scan_export.json'
    return response

@app.route('/api/clear', methods=['POST'])
def api_clear():
    global SCAN_CACHE
    if SCAN_STATUS.get("scanning", False):
        return jsonify({'success': False, 'message': '扫描进行中'})
    
    SCAN_CACHE.clear()
    return jsonify({'success': True})

if __name__ == '__main__':
    print("""
==========================================
   家庭网络端口管理器 (Home Port Manager)
==========================================
访问: http://0.0.0.0:2333
    """)
    app.run(host='0.0.0.0', port=2333, debug=False, threaded=True)
