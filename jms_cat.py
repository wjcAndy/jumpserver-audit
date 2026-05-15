# jms_collector_gaojing抑制.py
# JumpServer v2.x 审计数据采集服务

import requests
import sqlite3
import logging
import time
import signal
import json
from datetime import datetime, timedelta

# ===================== 配置区（改这里） =====================
CONFIG = {
    "jumpserver_url": "http://jumpserver.example.com",
    "username": "admin",            # JumpServer 登录用户名
    "password": "Abc123456&",          # JumpServer 登录密码

    "interval": 300,                 # 采集间隔（秒）
    "db_path": "./jumpserver_audit.db",

    # 告警 Webhook（不填则不推送）
    "alert_webhook": "https://open.feishu.cn/*********",             # 企业微信/钉钉/飞书 webhook

    # 高危命令关键词
    "dangerous_commands": [
        "rm -rf /", "rm -rf /*", "mkfs", "dd if=",
        "chmod 777 /", "chmod -R 777", "> /dev/sd",
        "shutdown", "reboot", "halt", "init 0", "init 6",
        "passwd root", "userdel", "groupdel",
        "iptables -F", ":(){:|:&};:",
        "kill -9", "kill -9 -1", "killall",
    ],

    # 敏感资产 IP（访问即告警）
    "sensitive_assets": [],
}

# ===================== 日志 =====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('./collector.log', encoding='utf-8'),
    ]
)
logger = logging.getLogger(__name__)


# ===================== 数据库 =====================
def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            ip TEXT,
            city TEXT,
            status TEXT,
            reason TEXT,
            user_agent TEXT,
            collected_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(timestamp, username, ip)
        );

        CREATE TABLE IF NOT EXISTS command_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            timestamp TEXT,
            username TEXT,
            asset TEXT,
            asset_ip TEXT,
            command TEXT,
            risk_level INTEGER DEFAULT 0,
            risk_reason TEXT,
            collected_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(session_id, timestamp, command)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE,
            protocol TEXT,
            username TEXT,
            asset TEXT,
            asset_ip TEXT,
            system_user TEXT,
            login_from TEXT,
            date_start TEXT,
            date_end TEXT,
            duration INTEGER,
            is_finished INTEGER,
            command_amount INTEGER,
            collected_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS sync_state (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_login_ts ON login_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_login_user ON login_logs(username);
        CREATE INDEX IF NOT EXISTS idx_login_status ON login_logs(status);
        CREATE INDEX IF NOT EXISTS idx_cmd_ts ON command_records(timestamp);
        CREATE INDEX IF NOT EXISTS idx_cmd_user ON command_records(username);
        CREATE INDEX IF NOT EXISTS idx_cmd_risk ON command_records(risk_level);
    """)
    conn.commit()
    return conn


def get_sync_time(conn: sqlite3.Connection, key: str) -> str:
    row = conn.execute("SELECT value FROM sync_state WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def set_sync_time(conn: sqlite3.Connection, key: str, value: str):
    conn.execute("INSERT OR REPLACE INTO sync_state(key, value) VALUES(?, ?)", (key, value))
    conn.commit()
# 在 jms_collector_gaojing抑制.py 顶部附近加一个工具函数

def safe_str(value, default="") -> str:
    """把可能是 dict/list 的值安全转成字符串"""
    if value is None:
        return default
    if isinstance(value, dict):
        return str(value.get("value", "") or value.get("label", "") or default)
    if isinstance(value, (list, tuple)):
        return str(value)
    return str(value)


def safe_int(value, default=0) -> int:
    """安全转 int"""
    if value is None:
        return default
    if isinstance(value, dict):
        value = value.get("value", default)
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


# ===================== JumpServer v2.x 客户端 =====================
class JumpServerV2Client:

    def __init__(self, url: str, username: str, password: str):
        self.url = url.rstrip('/')
        self.username = username
        self.password = password
        self.token = None
        self.token_expire = None

    def _login(self):
        """用户名密码换取 Token"""
        logger.info(f"正在登录 JumpServer (用户: {self.username}) ...")
        resp = requests.post(
            f"{self.url}/api/v1/authentication/tokens/",
            json={
                "username": self.username,
                "password": self.password,
            },
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()

        self.token = data["token"]
        keyword = data.get("keyword", "Bearer")  # Bearer

        # 解析过期时间，提前 5 分钟刷新
        expire_str = data.get("date_expired", "")
        if expire_str:
            try:
                # 格式: "2026/05/15 16:37:41 +0800"
                expire_str_clean = expire_str.split(" +")[0]  # 去掉时区
                self.token_expire = datetime.strptime(expire_str_clean, "%Y/%m/%d %H:%M:%S") - timedelta(minutes=5)
            except:
                self.token_expire = datetime.now() + timedelta(hours=23)
        else:
            self.token_expire = datetime.now() + timedelta(hours=23)

        user_info = data.get("user", {})
        logger.info(f"登录成功! 用户: {user_info.get('name', '')} | Token 有效期至: {self.token_expire}")

    def _ensure_token(self):
        if not self.token or datetime.now() >= self.token_expire:
            self._login()

    def _headers(self) -> dict:
        self._ensure_token()
        return {"Authorization": f"Bearer {self.token}"}

    def get(self, endpoint: str, params: dict = None) -> dict:
        resp = requests.get(
            f"{self.url}/api/v1/{endpoint.lstrip('/')}",
            headers=self._headers(),
            params=params,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def paginate(self, endpoint: str, params: dict = None, limit: int = 100):
        """自动翻页"""
        params = params or {}
        params["limit"] = limit
        params["offset"] = 0

        while True:
            data = self.get(endpoint, params)
            for item in data.get("results", []):
                yield item
            if not data.get("next"):
                break
            params["offset"] += limit


# ===================== 告警推送 =====================
def send_alert(webhook_url: str, title: str, content: str):
    if not webhook_url:
        return
    try:
        if "qyapi.weixin.qq.com" in webhook_url:
            payload = {"msgtype": "markdown", "markdown": {"content": f"### {title}\n{content}"}}
        elif "oapi.dingtalk.com" in webhook_url:
            payload = {"msgtype": "markdown", "markdown": {"title": title, "text": f"### {title}\n{content}"}}
        elif "open.feishu.cn" in webhook_url:
            payload = {"msg_type": "text", "content": {"text": f"{title}\n{content}"}}
        else:
            payload = {"title": title, "content": content}
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception as e:
        logger.error(f"告警推送失败: {e}")


# ===================== 命令风险检查 =====================
def check_command_risk(command: str, cfg: dict) -> dict:
    cmd = command.strip().lower()

    for kw in cfg["dangerous_commands"]:
        if kw.lower() in cmd:
            return {"level": 2, "reason": f"高危关键词: {kw}"}

    if cmd.startswith("sudo su") or cmd.startswith("sudo -i"):
        return {"level": 1, "reason": "sudo 提权"}
    if "find" in cmd and "-delete" in cmd:
        return {"level": 2, "reason": "find -delete 批量删除"}
    if "crontab" in cmd and "-e" in cmd:
        return {"level": 1, "reason": "修改计划任务"}

    return {"level": 0, "reason": ""}


# ===================== 采集函数 =====================
def collect_login_logs(client: JumpServerV2Client, conn: sqlite3.Connection, cfg: dict):
    last = get_sync_time(conn, "login_last")
    params = {}
    if last:
        params["date_from"] = last

    count = 0
    alerts = []
    for item in client.paginate("audits/login-logs/", params):
        status_raw = item.get("status")
        if isinstance(status_raw, dict):
            status_raw = status_raw.get("value", 0)
        status_label = "success" if status_raw == 1 else "failed"

        try:
            conn.execute(
                """INSERT OR IGNORE INTO login_logs
                   (timestamp, username, ip, city, status, reason, user_agent)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    safe_str(item.get("datetime")),
                    safe_str(item.get("username")),
                    safe_str(item.get("ip")),
                    safe_str(item.get("city")),
                    status_label,
                    safe_str(item.get("reason")),
                    safe_str(item.get("user_agent")),
                )
            )
        except sqlite3.IntegrityError:
            pass
        count += 1

        if status_label == "failed":
            logger.warning(f"登录失败: {item.get('username')}@{item.get('ip')} | {item.get('reason')}")
            alerts.append(
                f"**用户**: {item.get('username')}\n"
                f"**IP**: {item.get('ip')}\n"
                f"**原因**: {item.get('reason')}\n"
                f"**时间**: {item.get('datetime')}"
            )

    conn.commit()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    set_sync_time(conn, "login_last", now)

    if count:
        logger.info(f"登录日志: 采集 {count} 条")

    for alert in alerts[:5]:
        send_alert(cfg["alert_webhook"], "⚠️ 登录失败告警", alert)


def collect_commands(client: JumpServerV2Client, conn: sqlite3.Connection, cfg: dict):
    last = get_sync_time(conn, "command_last")
    params = {}
    if last:
        params["date_from"] = last

    count = 0
    risk_count = 0
    alerts = []

    for item in client.paginate("terminal/commands/", params):
        cmd = safe_str(item.get("input"))
        risk = check_command_risk(cmd, cfg)

        try:
            conn.execute(
                """INSERT OR IGNORE INTO command_records
                   (session_id, timestamp, username, asset, asset_ip, command, risk_level, risk_reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    safe_str(item.get("session")),
                    safe_str(item.get("timestamp")),
                    safe_str(item.get("user")),
                    safe_str(item.get("asset")),
                    safe_str(item.get("asset_ip")),
                    cmd,
                    risk["level"],
                    risk["reason"],
                )
            )
        except sqlite3.IntegrityError:
            pass
        count += 1

        if risk["level"] >= 2:
            risk_count += 1
            logger.warning(f"🚨 高危命令: {item.get('user')}@{item.get('asset_ip')} → {cmd}")
            alerts.append(
                f"**用户**: {item.get('user')}\n"
                f"**资产**: {item.get('asset')} ({item.get('asset_ip')})\n"
                f"**命令**: `{cmd}`\n"
                f"**原因**: {risk['reason']}\n"
                f"**时间**: {item.get('timestamp')}"
            )

    conn.commit()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    set_sync_time(conn, "command_last", now)

    if count:
        logger.info(f"命令记录: 采集 {count} 条, 高危 {risk_count} 条")

    for alert in alerts[:5]:
        send_alert(cfg["alert_webhook"], "🚨 高危命令告警", alert)


def collect_sessions(client: JumpServerV2Client, conn: sqlite3.Connection, cfg: dict):
    last = get_sync_time(conn, "session_last")
    params = {}
    if last:
        params["date_from"] = last

    count = 0
    for item in client.paginate("terminal/sessions/", params):
        # 某些版本 is_finished 也是 dict
        is_finished_raw = item.get("is_finished")
        if isinstance(is_finished_raw, dict):
            is_finished_raw = is_finished_raw.get("value", False)

        conn.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id, protocol, username, asset, asset_ip,
                system_user, login_from, date_start, date_end,
                duration, is_finished, command_amount)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                safe_str(item.get("id")),
                safe_str(item.get("protocol")),
                safe_str(item.get("user")),
                safe_str(item.get("asset")),
                safe_str(item.get("asset_ip")),
                safe_str(item.get("system_user")),
                safe_str(item.get("login_from")),
                safe_str(item.get("date_start")),
                safe_str(item.get("date_end")),
                safe_int(item.get("duration")),
                1 if is_finished_raw else 0,
                safe_int(item.get("command_amount")),
            )
        )
        count += 1

        if item.get("asset_ip") in cfg.get("sensitive_assets", []):
            send_alert(
                cfg["alert_webhook"], "🔒 敏感资产访问",
                f"**用户**: {item.get('user')}\n"
                f"**资产**: {item.get('asset')} ({item.get('asset_ip')})\n"
                f"**时间**: {item.get('date_start')}"
            )

    conn.commit()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    set_sync_time(conn, "session_last", now)

    if count:
        logger.info(f"会话记录: 采集 {count} 条")

# ===================== 统计摘要 =====================
def print_summary(conn: sqlite3.Connection):
    """每轮采集后打印统计"""
    # 今日登录
    row = conn.execute(
        "SELECT COUNT(*) FROM login_logs WHERE timestamp >= date('now','localtime')"
    ).fetchone()
    today_logins = row[0] if row else 0

    row = conn.execute(
        "SELECT COUNT(*) FROM login_logs WHERE status='failed' AND timestamp >= date('now','localtime')"
    ).fetchone()
    today_failed = row[0] if row else 0

    # 今日命令
    row = conn.execute(
        "SELECT COUNT(*) FROM command_records WHERE timestamp >= date('now','localtime')"
    ).fetchone()
    today_cmds = row[0] if row else 0

    row = conn.execute(
        "SELECT COUNT(*) FROM command_records WHERE risk_level >= 2 AND timestamp >= date('now','localtime')"
    ).fetchone()
    today_risks = row[0] if row else 0

    logger.info(f"📊 今日统计 | 登录: {today_logins} (失败: {today_failed}) | 命令: {today_cmds} (高危: {today_risks})")


# ===================== 主入口 =====================
def main():
    cfg = CONFIG

    logger.info("=" * 55)
    logger.info("JumpServer v2.x 审计采集服务")
    logger.info(f"目标: {cfg['jumpserver_url']}")
    logger.info(f"间隔: {cfg['interval']}秒")
    logger.info("=" * 55)

    db = init_db(cfg["db_path"])
    client = JumpServerV2Client(cfg["jumpserver_url"], cfg["username"], cfg["password"])

    # 优雅退出
    running = True
    def stop(sig, frame):
        nonlocal running
        running = False
        logger.info("收到退出信号，正在停止 ...")
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    # 首次先拿 Token 验证连通
    try:
        client._login()
    except Exception as e:
        logger.error(f"登录失败: {e}")
        return

    # 主循环
    while running:
        try:
            logger.info("--- 开始采集 ---")
            collect_login_logs(client, db, cfg)
            collect_commands(client, db, cfg)
            collect_sessions(client, db, cfg)
            print_summary(db)
            logger.info(f"--- 采集完成，等待 {cfg['interval']}秒 ---\n")
        except requests.exceptions.ConnectionError:
            logger.error("连接 JumpServer 失败，60秒后重试")
            time.sleep(60)
            continue
        except Exception as e:
            logger.error(f"采集异常: {e}", exc_info=True)

        for _ in range(cfg["interval"]):
            if not running:
                break
            time.sleep(1)

    db.close()
    logger.info("采集服务已停止")


if __name__ == "__main__":
    main()
