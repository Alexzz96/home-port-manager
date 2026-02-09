#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
家庭网络端口管理器 - Home Port Manager
一键扫描、可视化、管理内网设备端口

使用方法:
    python app.py
    
然后浏览器访问: http://127.0.0.1:2333
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
                # 更新进度更频繁 - 每50个端口或每1%更新一次
                if progress_callback and (scanned[0] % 50 == 0 or scanned[0] % max(1, total // 100) == 0):
                    progress_callback(scanned[0], total)
        
        # 确保最后100%进度被报告
        if progress_callback:
            progress_callback(total, total)
        
        open_ports.sort(key=lambda x: x['port'])
        print(f"[完成] 发现 {len(open_ports)} 个开放端口")
        return open_ports
    
    def ping_scan(self):
        base_ip = '.'.join(self.network.split('.')[:3])
        found = []
        timeout_ms = 500
        workers = 100
        total_hosts = 254
        
        print(f"[设备发现] 扫描网段 {base_ip}.1-254 ...")
        SCAN_STATUS["current_device"] = "正在发现内网设备..."
        
        def ping_host(suffix):
            while SCAN_STATUS.get("paused", False):
                time.sleep(0.5)
            
            ip = f"{base_ip}.{suffix}"
            # 更新进度
            progress = int((suffix / total_hosts) * 100)
            SCAN_STATUS["progress"] = progress
            
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

# ======== HTML Frontend ========
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>家庭网络端口管理器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, sans-serif; background: #f2f2f7; min-height: 100vh; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { background: #fff; color: #000; padding: 30px; border-radius: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .header h1 { font-size: 28px; margin-bottom: 6px; font-weight: 700; }
        .header p { font-size: 14px; color: #8e8e93; }
        .controls { background: #fff; padding: 16px 20px; border-radius: 16px; margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        button { background: #007aff; color: white; border: none; padding: 10px 18px; border-radius: 10px; cursor: pointer; font-size: 14px; font-weight: 500; transition: all 0.2s; }
        button:hover { background: #0051d5; }
        button:active { transform: scale(0.96); }
        button:disabled { background: #c7c7cc; cursor: not-allowed; transform: none; }
        button.danger { background: #ff3b30; }
        button.danger:hover { background: #d63029; }
        select { padding: 10px 14px; border-radius: 10px; border: 1px solid #c7c7cc; font-size: 14px; background: #fff; cursor: pointer; outline: none; }
        select:hover, select:focus { border-color: #007aff; }
        .scanning { animation: pulse 1.5s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.6; } 100% { opacity: 1; } }
        .device-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 16px; }
        .device-card { background: #fff; border-radius: 16px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); transition: all 0.2s; cursor: pointer; }
        .device-card:hover { box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        .device-card.selected { border: 2px solid #007aff; }
        .device-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .device-title { font-size: 17px; font-weight: 600; color: #000; font-family: "SF Mono", Monaco, monospace; }
        .device-name-input { font-size: 12px; color: #007aff; background: transparent; border: none; cursor: pointer; padding: 2px 6px; border-radius: 4px; text-align: right; height: 22px; line-height: 22px; outline: none; }
        .device-name-input:hover { background: #f2f2f7; }
        .device-name-input:focus { background: #e5f0ff; }
        .device-name-input::placeholder { color: #c7c7cc; font-size: 11px; }
        .device-meta { font-size: 13px; color: #8e8e93; margin-bottom: 14px; padding: 10px; background: #f2f2f7; border-radius: 10px; }
        .ports-list { border-top: 1px solid #e5e5ea; padding-top: 14px; max-height: 280px; overflow-y: auto; }
        .ports-list::-webkit-scrollbar { width: 6px; }
        .ports-list::-webkit-scrollbar-track { background: transparent; }
        .ports-list::-webkit-scrollbar-thumb { background: #c7c7cc; border-radius: 3px; }
        .port-item { display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; margin-bottom: 4px; border-radius: 10px; transition: background 0.15s; background: #f9f9fb; cursor: pointer; }
        .port-item:hover { background: #f2f2f7; }
        .port-number { font-family: "SF Mono", Monaco, monospace; font-weight: 600; background: #007aff; color: white; padding: 5px 11px; border-radius: 8px; font-size: 14px; min-width: 46px; text-align: center; }
        .risk-高 { color: #fff; background: #ff3b30; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 500; }
        .risk-中 { color: #fff; background: #ff9500; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 500; }
        .risk-低 { color: #fff; background: #34c759; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 500; }
        .empty { text-align: center; padding: 60px; color: #8e8e93; }
        .empty p { font-size: 16px; margin-bottom: 8px; }
        .progress { background: #fff; padding: 16px; border-radius: 16px; margin-bottom: 20px; display: none; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .progress-bar { height: 8px; background: #e5e5ea; border-radius: 4px; overflow: hidden; }
        .progress-fill { height: 100%; background: #007aff; width: 0%; transition: width 0.3s ease; border-radius: 4px; }
        .tabs { display: flex; gap: 8px; margin-bottom: 20px; background: #fff; padding: 8px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .tab { padding: 10px 24px; cursor: pointer; border-radius: 10px; font-weight: 500; transition: all 0.2s; color: #8e8e93; font-size: 14px; }
        .tab:hover { color: #007aff; }
        .tab.active { background: #007aff; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏠 家庭网络端口管理器</h1>
            <p>自动发现内网设备 | 扫描开放端口 | 识别安全风险</p>
        </div>
        
        <div class="controls">
            <button id="scanDevicesBtn" onclick="scanDevices()">🔍 扫描设备</button>
            <button id="scanPortsBtn" onclick="scanSelectedDevicePorts()" disabled style="background: #8e8e93;">📡 扫描选中设备端口</button>
            <button id="scanAllBtn" onclick="scanAll()">🌐 扫描全部</button>
            <button onclick="exportData()">📊 导出JSON</button>
            <button onclick="clearData()" class="danger">🗑️ 清除数据</button>
            <select id="speedSelect" onchange="changeSpeed(this.value)">
                <option value="fast" selected>🚀 极速</option>
                <option value="standard">🔄 常规</option>
            </select>
            <select id="portModeSelect">
                <option value="full" selected>🌐 全端口1-65535</option>
                <option value="common">📋 常用端口</option>
            </select>
            <span id="statusText" style="color: #666; margin-left: 10px;"></span>
        </div>
        
        <div class="progress" id="progressDiv">
            <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 10px;">
                <div id="progressText" style="color: #666;"></div>
                <button id="pauseBtn" onclick="togglePause()" style="display: none; background: #ff9500;">⏸️ 暂停</button>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab active" onclick="switchTab('devices')" id="tab-devices">📱 设备列表</div>
        </div>
        
        <div id="content-devices" class="tab-content active">
            <div id="scanningArea" style="display: none; background: white; border-radius: 12px; padding: 20px; margin-bottom: 20px;">
                <h3 style="margin-bottom: 15px;">🔍 正在扫描...</h3>
                <div id="scanningDevice" style="color: #666; margin-bottom: 10px;"></div>
                <div id="foundPorts" style="display: flex; flex-wrap: wrap; gap: 8px;"></div>
            </div>
            
            <div id="devicesList">
                <div class="empty">
                    <p>点击"扫描设备"开始发现内网设备</p>
                    <p style="font-size: 12px; color: #999; margin-top: 5px;">点击"扫描全部"可扫描所有设备的端口</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        let scanInterval;
        let selectedDeviceIp = null;
        
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.getElementById('tab-' + tab).classList.add('active');
            document.getElementById('content-' + tab).classList.add('active');
        }
        
        function changeSpeed(mode) {
            fetch('/api/speed', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({mode: mode})
            });
        }
        
        function scanDevices() {
            setScanningState(true);
            document.getElementById('statusText').textContent = '正在发现内网设备...';
            document.getElementById('progressDiv').style.display = 'block';
            
            fetch('/api/scan/devices')
                .then(r => r.json())
                .then(data => {
                    if (data.error) { alert(data.error); setScanningState(false); return; }
                    scanInterval = setInterval(() => checkStatus('devices'), 1000);
                })
                .catch(err => { alert('扫描失败: ' + err); setScanningState(false); });
        }
        
        function scanSelectedDevicePorts() {
            if (!selectedDeviceIp) { alert('请先选择一个设备'); return; }
            setScanningState(true);
            const portMode = document.getElementById('portModeSelect').value;
            document.getElementById('statusText').textContent = `正在扫描 ${selectedDeviceIp}...`;
            document.getElementById('progressDiv').style.display = 'block';
            
            fetch(`/api/scan/ports/${selectedDeviceIp}?mode=${portMode}`)
                .then(r => r.json())
                .then(data => {
                    if (data.error) { alert(data.error); setScanningState(false); return; }
                    scanInterval = setInterval(() => checkStatus('ports'), 1000);
                })
                .catch(err => { alert('扫描失败: ' + err); setScanningState(false); });
        }
        
        function scanAll() {
            setScanningState(true);
            const portMode = document.getElementById('portModeSelect').value;
            document.getElementById('statusText').textContent = '扫描中...';
            document.getElementById('scanningArea').style.display = 'block';
            document.getElementById('devicesList').innerHTML = '';
            document.getElementById('progressDiv').style.display = 'block';
            
            fetch(`/api/scan/all?mode=${portMode}`)
                .then(r => r.json())
                .then(data => {
                    if (data.error) { alert(data.error); setScanningState(false); return; }
                    scanInterval = setInterval(() => checkStatus('all'), 1000);
                })
                .catch(err => { alert('扫描失败: ' + err); setScanningState(false); });
        }
        
        function setScanningState(scanning) {
            document.getElementById('scanDevicesBtn').disabled = scanning;
            document.getElementById('scanPortsBtn').disabled = scanning || !selectedDeviceIp;
            document.getElementById('scanAllBtn').disabled = scanning;
            const pauseBtn = document.getElementById('pauseBtn');
            if (scanning) {
                document.getElementById('scanDevicesBtn').classList.add('scanning');
                document.getElementById('scanAllBtn').classList.add('scanning');
                document.getElementById('progressDiv').style.display = 'block';
                pauseBtn.style.display = 'inline-block';
                pauseBtn.textContent = '⏸️ 暂停';
                pauseBtn.style.background = '#ff9500';
            } else {
                document.getElementById('scanDevicesBtn').classList.remove('scanning');
                document.getElementById('scanAllBtn').classList.remove('scanning');
                pauseBtn.style.display = 'none';
            }
        }
        
        function togglePause() {
            const pauseBtn = document.getElementById('pauseBtn');
            const isPaused = pauseBtn.textContent.includes('继续');
            
            fetch('/api/scan/pause', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({paused: !isPaused})
            }).then(r => r.json()).then(data => {
                if (data.paused) {
                    pauseBtn.textContent = '▶️ 继续';
                    pauseBtn.style.background = '#28a745';
                } else {
                    pauseBtn.textContent = '⏸️ 暂停';
                    pauseBtn.style.background = '#ff9500';
                }
            });
        }
        
        function checkStatus(type) {
            fetch('/api/scan/stream').then(r => r.json()).then(data => {
                const progress = data.progress || 0;
                document.getElementById('progressFill').style.width = progress + '%';
                document.getElementById('progressText').textContent = progress + '%';
                
                let statusText = '就绪';
                if (data.scanning) {
                    if (type === 'devices') statusText = `发现设备中... ${progress}%`;
                    else if (type === 'ports') statusText = `扫描端口 ${data.current_device || selectedDeviceIp}... ${progress}%`;
                    else statusText = data.current_device ? `扫描中: ${data.current_device} (${progress}%)` : `扫描中... ${progress}%`;
                }
                document.getElementById('statusText').textContent = statusText;
                
                // 始终显示扫描区域和进度条当扫描中
                if (data.scanning) {
                    document.getElementById('scanningArea').style.display = 'block';
                    document.getElementById('progressDiv').style.display = 'block';
                    document.getElementById('scanningDevice').textContent = data.current_device || '扫描中...';
                    
                    const portsDiv = document.getElementById('foundPorts');
                    if (data.found_ports && data.found_ports.length > 0) {
                        portsDiv.innerHTML = data.found_ports.map(p => 
                            `<span style="background: #007aff; color: white; padding: 6px 12px; border-radius: 8px; font-size: 13px; margin: 2px; display: inline-block;">${p.port}</span>`
                        ).join('');
                    } else {
                        portsDiv.innerHTML = '<span style="color: #999; font-size: 13px;">等待发现开放端口...</span>';
                    }
                }
                
                if (!data.scanning) {
                    clearInterval(scanInterval);
                    setScanningState(false);
                    document.getElementById('statusText').textContent = '扫描完成';
                    setTimeout(() => {
                        document.getElementById('progressDiv').style.display = 'none';
                        document.getElementById('scanningArea').style.display = 'none';
                    }, 2000);
                    loadDevices();
                }
            }).catch(err => {
                console.error('获取状态失败:', err);
            });
        }
        
        function loadDevices() {
            fetch('/api/devices').then(r => r.json()).then(devices => {
                if (devices.length === 0) {
                    document.getElementById('devicesList').innerHTML = '<div class="empty"><p>未发现设备</p></div>';
                    return;
                }
                
                const html = devices.map(d => `
                    <div class="device-card ${selectedDeviceIp === d.ip ? 'selected' : ''}" onclick="selectDevice('${d.ip}', this)">
                        <div class="device-header">
                            <div>
                                <div class="device-title">${d.ip}</div>
                                ${d.custom_name ? `<div style="font-size: 13px; color: #34c759; margin-top: 4px; font-weight: 500;">${d.custom_name}</div>` : ''}
                            </div>
                            <input type="text" value="${d.custom_name || ''}" placeholder="添加备注" class="device-name-input"
                                onclick="event.stopPropagation();" onkeydown="if(event.key==='Enter'){saveDeviceName('${d.ip}', this.value);this.blur();}" onblur="saveDeviceName('${d.ip}', this.value)">
                        </div>
                        <div class="device-meta">MAC: ${d.mac}</div>
                        <div class="ports-list">
                            ${d.ports.map(p => `
                                <div class="port-item" onclick="window.open('http://${d.ip}:${p.port}/', '_blank')">
                                    <span class="port-number">${p.port}</span>
                                    <span style="flex: 1; margin: 0 12px; color: #333;">${p.service}</span>
                                    <span class="risk-${p.risk}">${p.risk}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `).join('');
                
                document.getElementById('devicesList').innerHTML = `<div class="device-grid">${html}</div>`;
            });
        }
        
        function saveDeviceName(ip, name) {
            fetch('/api/device/note', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip: ip, name: name})
            }).then(() => loadDevices());
        }
        
        function selectDevice(ip, element) {
            selectedDeviceIp = ip;
            document.getElementById('scanPortsBtn').disabled = false;
            document.getElementById('scanPortsBtn').style.background = '#007aff';
            document.getElementById('scanPortsBtn').textContent = `📡 扫描 ${ip}`;
            
            document.querySelectorAll('.device-card').forEach(card => card.classList.remove('selected'));
            element.classList.add('selected');
        }
        
        function clearData() {
            if (!confirm('确定要清除所有扫描数据吗？')) return;
            fetch('/api/clear', {method: 'POST'}).then(() => {
                document.getElementById('devicesList').innerHTML = '<div class="empty"><p>数据已清除</p></div>';
                selectedDeviceIp = null;
            });
        }
        
        function exportData() {
            window.open('/api/export', '_blank');
        }
        
        window.onload = () => {
            loadDevices();
        };
    </script>
</body>
</html>'''

@app.route('/')
def index():
    return HTML_TEMPLATE

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
