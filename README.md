# jumpserver-audit

# JumpServer 审计采集服务（增强版）

> 基于 JumpServer v2.x API 的自动化审计数据采集与实时告警服务，支持敏感资产高频监控、高危命令检测、登录异常分析，并通过飞书/钉钉/企业微信推送告警通知。

---

## 功能概览

| 功能模块 | 说明 |
|---|---|
| **登录日志采集** | 自动拉取 JumpServer 登录记录，区分成功/失败状态 |
| **会话记录采集** | 采集所有协议会话（SSH/RDP/MySQL 等），记录时长、来源等 |
| **命令记录采集** | 按会话维度采集执行命令，自动标记风险等级 |
| **高危命令检测** | 内置 20+ 高危命令关键词匹配，触发即时告警 |
| **敏感资产监控** | 对指定资产以 5 秒间隔高频采集，会话结束自动发送命令汇总 |
| **登录失败检测** | 滑动窗口内失败次数超阈值自动告警，含冷却机制防重复 |
| **多通道告警** | 支持飞书（卡片消息）、钉钉（Markdown）、企业微信（Markdown） |
| **数据自动清理** | 日志文件 7 天轮转，SQLite 过期数据每日自动清理 |
| **增量同步** | 基于时间戳增量拉取，重启不丢数据、不重复采集 |

---

## 系统要求

- **Python**: 3.6+
- **JumpServer**: v2.x（已适配 v2.x REST API）
- **操作系统**: Linux / macOS / Windows

---

## 依赖安装

```bash
pip install requests
```

> `sqlite3`、`logging`、`threading` 等均为 Python 标准库，无需额外安装。

---

## 文件结构

```
jumpserver-collector/
├── jms_collector_研发环境.py    # 主程序
├── jumpserver_audit.db         # SQLite 数据库（运行后自动生成）
├── collector.log               # 日志文件（运行后自动生成）
└── README.md
```

---

## 快速开始

### 1. 修改配置

打开 `jms_collector_研发环境.py`，修改顶部 `CONFIG` 字典：

```python
CONFIG = {
    # JumpServer 连接信息
    "jumpserver_url": "http://your-jumpserver-ip",
    "username": "admin",
    "password": "your-password",

    # 采集间隔（秒）
    "interval": 300,

    # 数据库和日志路径
    "db_path": "./jumpserver_audit.db",
    "log_path": "./collector.log",

    # 告警 Webhook（按需填写，留空则不发送）
    "alert_feishu_webhook": "",
    "alert_dingtalk_webhook": "",
    "alert_wechat_webhook": "",

    # 敏感资产 IP 列表（5秒间隔高频监控）
    "sensitive_assets": [
        "192.168.200.11",
    ],

    # 登录失败检测参数
    "login_fail_threshold": 5,   # 失败次数阈值
    "login_fail_window": 300,    # 检测窗口（秒）

    # 数据保留天数
    "data_retention_days": 7,
}
```

### 2. 启动采集

```bash
python3 jms_collector_研发环境.py
```

### 3. 后台运行（推荐）

```bash
# 使用 nohup
nohup python3 jms_collector_研发环境.py > /dev/null 2>&1 &

# 或使用 systemd（见下方部署章节）
```

---

## 配置详解

### JumpServer 连接

| 参数 | 说明 | 示例 |
|---|---|---|
| `jumpserver_url` | JumpServer 访问地址（不带末尾 `/`） | `http://10.0.0.1` |
| `username` | API 登录用户名 | `admin` |
| `password` | API 登录密码 | `****` |

> 账号需要具备 **审计员** 或 **管理员** 权限，否则部分 API 接口无法访问。

### 告警 Webhook

按需填写，支持同时配置多个通道（并行发送）：

| 通道 | 配置方式 |
|---|---|
| **飞书** | 群设置 → 群机器人 → 自定义机器人 → 复制 Webhook 地址 |
| **钉钉** | 群设置 → 智能群助手 → 添加机器人 → 自定义 → 复制 Webhook |
| **企业微信** | 群聊 → 群机器人 → 添加 → 新创建一个机器人 → 复制 Webhook |

### 敏感资产监控

```python
"sensitive_assets": [
    "192.168.200.11",
    "10.0.0.50",
]
```

- 配置后会启动独立线程，以 **5 秒间隔** 高频采集这些资产的会话和命令
- 会话开始时触发「敏感资产登录告警」
- 会话结束时触发「会话结束报告」，包含完整命令列表

### 高危命令检测

内置检测规则：

| 风险等级 | 触发条件 |
|---|---|
| **Level 2（高危）** | `rm -rf /`、`mkfs`、`dd if=`、`chmod 777 /`、`shutdown`、`reboot`、`passwd root`、`userdel`、`iptables -F`、`kill -9 -1` 等 20+ 关键词 |
| **Level 2（高危）** | `find ... -delete` 批量删除 |
| **Level 1（警告）** | `sudo su`、`sudo -i` 提权操作 |
| **Level 1（警告）** | `crontab -e` 修改计划任务 |

可通过修改 `CONFIG["dangerous_commands"]` 列表自定义关键词。

---

## 数据库结构

数据库文件默认为 `./jumpserver_audit.db`（SQLite），包含以下表：

| 表名 | 用途 |
|---|---|
| `login_logs` | 登录日志（用户名、IP、城市、状态、原因、UA） |
| `command_records` | 命令记录（会话ID、命令内容、风险等级、风险原因） |
| `sessions` | 会话记录（协议、用户、资产、IP、时长、命令数） |
| `sensitive_session_tracking` | 敏感资产会话跟踪（标记是否已发送汇总报告） |
| `sync_state` | 同步状态（记录各采集模块的上次同步时间） |

所有表均建有索引，支持按时间、用户、状态、风险等级等维度快速查询。

---

## 采集架构

```
┌─────────────────────────────────────────────────┐
│                  主线程（Main Loop）                │
│                                                   │
│  每 300 秒执行一次：                                │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │
│  │ 登录日志采集  │  │ 会话记录采集  │  │ 命令记录采集│ │
│  └──────┬──────┘  └──────┬──────┘  └─────┬─────┘ │
│         └────────────┬───┘               │       │
│                      ▼                   │       │
│              登录失败检测 ◄───────────────┘       │
│                      │                           │
│                      ▼                           │
│              统计摘要 & 数据清理                    │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│             敏感资产线程（独立 Thread）              │
│                                                   │
│  每 5 秒执行一次：                                  │
│  ┌──────────────────────────────────────────────┐│
│  │ 1. 拉取最新会话 → 发现敏感资产新会话 → 即时告警  ││
│  │ 2. 按 session 拉取命令记录                     ││
│  │ 3. 已结束会话 → 发送命令汇总报告               ││
│  └──────────────────────────────────────────────┘│
└─────────────────────────────────────────────────┘
```

---

## 告警消息示例

### 高危命令告警

```
🚨 高危命令告警
───────────────
用户: ops01
资产: 生产数据库(DB-Master)
IP: 192.168.200.11
命令: rm -rf /var/log/*
风险原因: 高危关键词: rm -rf
时间: 2025-01-15 14:32:05
```

### 登录失败频次告警

```
⚠️ 登录失败频次告警
───────────────────
用户: testuser
失败次数: 8 次（最近 5 分钟）
来源 IP: 10.0.0.100, 10.0.0.101
时间范围: 2025-01-15 14:27:00 ~ 2025-01-15 14:32:00
```

### 敏感资产登录告警

```
🔒 敏感资产登录告警
───────────────────
用户: root
资产: 生产数据库(DB-Master)
IP: 192.168.200.11
协议: ssh
系统用户: root
登录来源: Web终端
时间: 2025-01-15 14:30:00
```

### 敏感资产会话结束报告

```
📋 敏感资产会话结束报告
──────────────────────
用户: root
资产: 生产数据库(DB-Master)
IP: 192.168.200.11
协议: ssh
开始时间: 2025-01-15 14:30:00
结束时间: 2025-01-15 15:10:00
命令数量: 12 条

1. ls -la (2025-01-15 14:30:15)
2. cd /opt/app (2025-01-15 14:30:20)
3. cat config.yml (2025-01-15 14:31:00)
...
```

---

## 日志说明

日志文件 `collector.log` 按天自动轮转，保留最近 7 天。

```
2025-01-15 14:30:00 [INFO] --- 开始常规采集 ---
2025-01-15 14:30:01 [INFO] 登录日志: 采集 23 条
2025-01-15 14:30:03 [INFO] 会话记录: 采集 15 条
2025-01-15 14:30:08 [INFO] 命令记录: 采集 342 条, 高危 2 条
2025-01-15 14:30:08 [WARNING] 🚨 高危命令: ops01@192.168.200.11 → rm -rf /tmp/*
2025-01-15 14:30:09 [INFO] 📊 今日统计 | 登录: 45 (失败:3) | 命令: 1024 (高危:5) | 会话: 30
2025-01-15 14:30:09 [INFO] --- 常规采集完成，等待 300秒 ---
```

---

## systemd 部署

创建服务文件 `/etc/systemd/system/jms-collector.service`：

```ini
[Unit]
Description=JumpServer Audit Collector
After=network.target

[Service]
Type=simple
User=ops
Group=ops
WorkingDirectory=/opt/jumpserver-collector
ExecStart=/usr/bin/python3 /opt/jumpserver-collector/jms_collector_研发环境.py
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable jms-collector
sudo systemctl start jms-collector

# 查看状态
sudo systemctl status jms-collector

# 查看日志
journalctl -u jms-collector -f
```

---

## 常见问题

### Q: 提示登录失败怎么办？

确认以下几点：
1. `jumpserver_url` 地址正确且可访问
2. 用户名和密码正确
3. 账号具有审计员或管理员权限
4. JumpServer 版本为 v2.x

### Q: 如何验证告警通道是否正常？

可临时将 `login_fail_threshold` 设为 `1`，登录失败一次即可触发告警。

### Q: 命令记录为空？

确认以下几点：
1. JumpServer 开启了「命令存储」功能
2. `terminal/commands/` API 接口可正常返回数据
3. 会话中有实际的命令输入（空会话不会有命令记录）

### Q: 敏感资产监控不生效？

确认以下几点：
1. `sensitive_assets` 中填写的是资产的 **IP 地址**，不是名称
2. IP 需与 JumpServer 中资产的 IP 字段完全匹配
3. 检查日志中是否有 `[敏感资产线程] 启动` 字样

### Q: 如何扩展更多高危命令？

修改 `CONFIG["dangerous_commands"]` 列表即可，添加后自动生效：

```python
"dangerous_commands": [
    # 已有的...
    "your_custom_command",
    "another_dangerous_keyword",
],
```

---

## API 接口依赖

本服务调用以下 JumpServer v2.x API 接口：

| 接口 | 用途 |
|---|---|
| `POST /api/v1/authentication/tokens/` | 获取认证 Token |
| `GET /api/v1/audits/login-logs/` | 登录日志 |
| `GET /api/v1/terminal/sessions/` | 会话记录 |
| `GET /api/v1/terminal/commands/` | 命令记录 |

---

## 许可

内部使用，请根据实际需求修改和分发。
