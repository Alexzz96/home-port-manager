# Home Port Manager

家庭网络端口管理器 - 局域网设备发现与端口扫描工具

## 功能特点

- 🔍 自动扫描局域网内所有在线设备
- 🌐 端口扫描 (常用端口 Top 1000 / 全端口 1-65535)
- 📝 设备备注管理
- 📊 JSON 数据导出
- ⚡ 极速/常规 两种扫描模式

## 技术栈

- Python 3.11+
- Flask
- Socket + ThreadPoolExecutor
- Docker

## 快速开始

### Docker 运行

```bash
docker-compose up -d
```

访问 http://localhost:5000

### 本地运行

```bash
pip install flask netifaces-plus
python app.py
```

## 端口服务识别

内置常见端口识别库，包括：
- Web 服务: 80, 443, 8080, 8443
- 远程桌面: 3389 (RDP), 5900 (VNC)
- 数据库: 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB)
- 文件共享: 445 (SMB), 139 (NetBIOS)
- IoT: 1883 (MQTT), 8883 (MQTTS)

## 安全说明

- 本工具仅用于个人家庭网络管理
- 扫描行为仅限局域网内
- 所有数据保存在本地

## 许可证

MIT License
