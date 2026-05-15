
# jms_collector_研发环境.py
# JumpServer v2.x 审计采集服务 - 增强版
# 支持: 飞书/钉钉/企业微信告警 | 登录失败频次 | 敏感资产监控 | 高危命令 | 7天数据保留

import threading
import os
import requests
import sqlite3
import logging
import time
import signal
import json
from datetime import datetime, timedelta
from collections import defaultdict
from logging.handlers import TimedRotatingFileHandler

# ===================== 配置区 =====================
CONFIG = {
    "jumpserver_url": "http://jumpserver.example.com",
    "username": "admin",
    "password": "Abc123456&",

    "interval": 300,
    "db_path": "./jumpserver_audit.db",
    "log_path": "./collector.log",

    "alert_feishu_webhook": "https://open.feishu.cn/******",
    "alert_dingtalk_webhook": "",
    "alert_wechat_webhook": "",

    "dangerous_commands": [
        "rm -rf /", "rm -rf /*", "mkfs", "dd if=",
        "chmod 777 /", "chmod -R 777", "> /dev/sd",
        "shutdown", "reboot", "halt", "init 0", "init 6",
        "passwd root", "userdel", "groupdel",
        "iptables -F", ":(){:|:&};:",
        "kill -9 -1", "killall",
    ],

    "sensitive_assets": [
        "192.168.200.11",
    ],

    "login_fail_threshold": 5,
    "login_fail_window": 300,

    "data_retention_days": 7,
}


# ===================== 时间标准化 =====================
def normalize_timestamp(ts: str) -> str:
    if not ts:
        return ""
    ts = ts.strip()
    for sep in [" +", "+"]:
        if sep in ts:
            ts = ts.split(sep)[0].strip()
    ts = ts.replace("/", "-")
    ts = ts.replace("T", " ")
    return ts


# ===================== 日志（7天自动轮转） =====================
def setup_logging(log_path: str):
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

    console = logging.StreamHandler()
    console.setFormatter(formatter)

    file_handler = TimedRotatingFileHandler(
        log_path, when='midnight', interval=1,
        backupCount=CONFIG["data_retention_days"], encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    file_handler.suffix = "%Y-%m-%d"

    _logger = logging.getLogger()
    _logger.setLevel(logging.INFO)
    _logger.addHandler(console)
    _logger.addHandler(file_handler)
    return _logger


logger = setup_logging(CONFIG["log_path"])


# ===================== IP 提取 =====================
def extract_ip_from_asset(asset: str) -> str:
    if not asset:
        return ""
    if "(" in asset and ")" in asset:
        return asset.split("(")[-1].rstrip(")")
    return ""


# ===================== 提取登录来源 =====================
def safe_label(value, default="") -> str:
    if value is None:
        return default
    if isinstance(value, dict):
        return value.get("label", "") or value.get("value", "") or default
    s = str(value)
    if "label" in s and isinstance(value, str):
        try:
            import ast
            d = ast.literal_eval(s)
            if isinstance(d, dict):
                return d.get("label", "") or d.get("value", "") or default
        except (ValueError, SyntaxError):
            pass
    return s


# ===================== 类型安全工具 =====================
def safe_str(value, default="") -> str:
    if value is None:
        return default
    if isinstance(value, dict):
        return str(value.get("value", "") or value.get("label", "") or default)
    if isinstance(value, (list, tuple)):
        return str(value)
    return str(value)


def safe_int(value, default=0) -> int:
    if value is None:
        return default
    if isinstance(value, dict):
        value = value.get("value", default)
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


# ===================== 数据库 =====================
def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
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

        CREATE TABLE IF NOT EXISTS sensitive_session_tracking (
            session_id TEXT PRIMARY KEY,
            username TEXT,
            asset TEXT,
            asset_ip TEXT,
            protocol TEXT,
            date_start TEXT,
            commands_reported INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime'))
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
        CREATE INDEX IF NOT EXISTS idx_cmd_session ON command_records(session_id);
    """)
    conn.commit()
    return conn


def get_sync_time(conn: sqlite3.Connection, key: str) -> str:
    row = conn.execute("SELECT value FROM sync_state WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def set_sync_time(conn: sqlite3.Connection, key: str, value: str):
    conn.execute("INSERT OR REPLACE INTO sync_state(key, value) VALUES(?, ?)", (key, value))
    conn.commit()


# ===================== JumpServer v2.x 客户端 =====================
class JumpServerV2Client:

    def __init__(self, url: str, username: str, password: str):
        self.url = url.rstrip('/')
        self.username = username
        self.password = password
        self.token = None
        self.token_expire = None

    def _login(self):
        logger.info(f"正在登录 JumpServer (用户: {self.username}) ...")
        resp = requests.post(
            f"{self.url}/api/v1/authentication/tokens/",
            json={"username": self.username, "password": self.password},
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        self.token = data["token"]

        expire_str = data.get("date_expired", "")
        if expire_str:
            try:
                expire_str_clean = expire_str.split(" +")[0]
                self.token_expire = datetime.strptime(
                    expire_str_clean, "%Y/%m/%d %H:%M:%S"
                ) - timedelta(minutes=5)
            except Exception:
                self.token_expire = datetime.now() + timedelta(hours=23)
        else:
            self.token_expire = datetime.now() + timedelta(hours=23)

        user_info = data.get("user", {})
        logger.info(f"登录成功! 用户: {user_info.get('name', '')} | Token有效期至: {self.token_expire}")

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


# ===================== 按 session 拉取命令 =====================
def collect_commands_by_session(client: JumpServerV2Client, conn: sqlite3.Connection, cfg: dict, session_id: str):
    count = 0
    for item in client.paginate("terminal/commands/", {"session_id": session_id}):
        cmd = safe_str(item.get("input"))
        if not cmd:
            cmd = safe_str(item.get("command"))

        risk = check_command_risk(cmd, cfg)
        ts = normalize_timestamp(safe_str(item.get("timestamp")))

        cmd_ip = safe_str(item.get("asset_ip"))
        if not cmd_ip:
            cmd_ip = extract_ip_from_asset(safe_str(item.get("asset")))

        try:
            conn.execute(
                """INSERT OR IGNORE INTO command_records
                   (session_id, timestamp, username, asset, asset_ip,
                    command, risk_level, risk_reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session_id, ts,
                    safe_str(item.get("user")),
                    safe_str(item.get("asset")), cmd_ip,
                    cmd, risk["level"], risk["reason"],
                ),
            )
        except sqlite3.IntegrityError:
            pass
        count += 1

        if risk["level"] >= 2:
            logger.warning(f"🚨 高危命令: {item.get('user')}@{cmd_ip} → {cmd}")
            msg = (
                f"**用户**: {item.get('user')}\n"
                f"**资产**: {item.get('asset')}\n"
                f"**IP**: {cmd_ip}\n"
                f"**命令**: `{cmd}`\n"
                f"**风险原因**: {risk['reason']}\n"
                f"**时间**: {ts}"
            )
            send_alert(cfg, "🚨 高危命令告警", msg)

    conn.commit()
    return count


# ===================== 告警推送（飞书 / 钉钉 / 企业微信） =====================
def _send_feishu(webhook: str, title: str, content: str, color: str = "red"):
    payload = {
        "msg_type": "interactive",
        "card": {
            "config": {"wide_screen_mode": True},
            "header": {
                "title": {"content": title, "tag": "plain_text"},
                "template": color,
            },
            "elements": [
                {
                    "tag": "div",
                    "text": {"content": content, "tag": "lark_md"},
                },
                {"tag": "hr"},
                {
                    "tag": "note",
                    "elements": [
                        {
                            "tag": "plain_text",
                            "content": f"JumpServer 审计监控 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                        }
                    ],
                },
            ],
        },
    }
    resp = requests.post(webhook, json=payload, timeout=10)
    resp.raise_for_status()


def _send_dingtalk(webhook: str, title: str, content: str):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    text = f"### {title}\n\n---\n\n{content}\n\n---\n\n> JumpServer 审计监控 | {now}"
    payload = {
        "msgtype": "markdown",
        "markdown": {"title": title, "text": text},
    }
    resp = requests.post(webhook, json=payload, timeout=10)
    resp.raise_for_status()


def _send_wechat(webhook: str, title: str, content: str):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    text = f"### {title}\n\n{content}\n\n> 来源: JumpServer 审计监控 | {now}"
    payload = {
        "msgtype": "markdown",
        "markdown": {"content": text},
    }
    resp = requests.post(webhook, json=payload, timeout=10)
    resp.raise_for_status()


def send_alert(cfg: dict, title: str, content: str):
    channels = [
        ("飞书", cfg.get("alert_feishu_webhook", ""), _send_feishu),
        ("钉钉", cfg.get("alert_dingtalk_webhook", ""), _send_dingtalk),
        ("企业微信", cfg.get("alert_wechat_webhook", ""), _send_wechat),
    ]
    sent_any = False
    for name, webhook, func in channels:
        if not webhook:
            continue
        try:
            func(webhook, title, content)
            sent_any = True
            logger.info(f"[{name}] 告警发送成功: {title}")
        except Exception as e:
            logger.error(f"[{name}] 告警发送失败: {e}")
    if not sent_any:
        logger.debug(f"未配置告警通道，跳过: {title}")


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


# ===================== 数据清理（保留N天） =====================
def cleanup_old_data(conn: sqlite3.Connection, cfg: dict):
    days = cfg.get("data_retention_days", 7)
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    tables = [
        ("login_logs", "timestamp"),
        ("command_records", "timestamp"),
        ("sessions", "date_start"),
        ("sensitive_session_tracking", "created_at"),
    ]

    total_deleted = 0
    for table, col in tables:
        cur = conn.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff,))
        if cur.rowcount > 0:
            total_deleted += cur.rowcount
            logger.info(f"清理 {table}: 删除 {cur.rowcount} 条 (早于 {cutoff})")

    conn.commit()

    if total_deleted:
        logger.info(f"数据清理完成: 共删除 {total_deleted} 条过期记录 (保留 {days} 天)")


# ===================== 告警1: 登录失败频次检测 =====================
_fail_alert_cooldown = {}


def check_login_failures(conn: sqlite3.Connection, cfg: dict):
    now = datetime.now()
    window = cfg.get("login_fail_window", 300)
    threshold = cfg.get("login_fail_threshold", 5)

    day_ago = (now - timedelta(hours=24)).strftime("%Y-%m-%d")
    rows = conn.execute("""
        SELECT username, timestamp, ip
        FROM login_logs
        WHERE status = 'failed'
          AND timestamp >= ?
        ORDER BY timestamp DESC
    """, (day_ago,)).fetchall()

    user_failures = defaultdict(list)

    for username, ts_raw, ip in rows:
        ts_clean = normalize_timestamp(ts_raw)
        try:
            ts_dt = datetime.strptime(ts_clean, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        diff = (now - ts_dt).total_seconds()
        if 0 <= diff <= window:
            user_failures[username].append((ts_dt, ip))

    for username, failures in user_failures.items():
        if len(failures) < threshold:
            continue

        last_alert = _fail_alert_cooldown.get(username)
        if last_alert and (now - last_alert).total_seconds() < window:
            continue

        _fail_alert_cooldown[username] = now

        timestamps = [f[0] for f in failures]
        ips = list(set(f[1] for f in failures))
        first_fail = min(timestamps).strftime("%Y-%m-%d %H:%M:%S")
        last_fail = max(timestamps).strftime("%Y-%m-%d %H:%M:%S")

        logger.warning(
            f"登录失败告警触发: {username} | "
            f"窗口内 {len(failures)} 次失败 | "
            f"范围 {first_fail} ~ {last_fail} | "
            f"窗口={window}秒, 当前={now.strftime('%Y-%m-%d %H:%M:%S')}"
        )

        msg = (
            f"**用户**: {username}\n"
            f"**失败次数**: {len(failures)} 次（最近 {window // 60} 分钟）\n"
            f"**来源 IP**: {', '.join(ips)}\n"
            f"**时间范围**: {first_fail} ~ {last_fail}\n"
            f"**当前时间**: {now.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        send_alert(cfg, "⚠️ 登录失败频次告警", msg)


# ===================== 常规采集: 登录日志 =====================
def collect_login_logs(client: JumpServerV2Client, conn: sqlite3.Connection, cfg: dict):
    last = get_sync_time(conn, "login_last")
    params = {}
    if last:
        params["date_from"] = last

    count = 0
    for item in client.paginate("audits/login-logs/", params):
        status_raw = item.get("status")
        if isinstance(status_raw, dict):
            status_raw = status_raw.get("value", 0)
        status_label = "success" if status_raw == 1 else "failed"

        ts = normalize_timestamp(safe_str(item.get("datetime")))

        try:
            conn.execute(
                """INSERT OR IGNORE INTO login_logs
                   (timestamp, username, ip, city, status, reason, user_agent)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    ts,
                    safe_str(item.get("username")),
                    safe_str(item.get("ip")),
                    safe_str(item.get("city")),
                    status_label,
                    safe_str(item.get("reason")),
                    safe_str(item.get("user_agent")),
                ),
            )
        except sqlite3.IntegrityError:
            pass
        count += 1

    conn.commit()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    set_sync_time(conn, "login_last", now)

    if count:
        logger.info(f"登录日志: 采集 {count} 条")


# ===================== 常规采集: 命令记录 =====================
def collect_commands(client: JumpServerV2Client, conn: sqlite3.Connection, cfg: dict):
    init_time = get_sync_time(conn, "initialized") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sessions = conn.execute("""
        SELECT session_id FROM sessions
        WHERE date_start >= ?
    """, (init_time,)).fetchall()

    total_count = 0
    total_risk = 0

    for (session_id,) in sessions:
        existing = conn.execute(
            "SELECT COUNT(*) FROM command_records WHERE session_id=?",
            (session_id,)
        ).fetchone()[0]

        if existing > 0:
            continue

        count = collect_commands_by_session(client, conn, cfg, session_id)
        total_count += count

        risk = conn.execute(
            "SELECT COUNT(*) FROM command_records WHERE session_id=? AND risk_level>=2",
            (session_id,)
        ).fetchone()[0]
        total_risk += risk

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    set_sync_time(conn, "command_last", now)

    if total_count:
        logger.info(f"命令记录: 采集 {total_count} 条, 高危 {total_risk} 条")


# ===================== 常规采集: 会话记录 =====================
def collect_sessions(client: JumpServerV2Client, conn: sqlite3.Connection, cfg: dict):
    last = get_sync_time(conn, "session_last")
    params = {}
    if last:
        params["date_from"] = last

    count = 0

    for item in client.paginate("terminal/sessions/", params):
        is_finished_raw = item.get("is_finished")
        if isinstance(is_finished_raw, dict):
            is_finished_raw = is_finished_raw.get("value", False)

        session_id = safe_str(item.get("id"))
        asset_ip = safe_str(item.get("asset_ip"))
        if not asset_ip:
            asset_ip = extract_ip_from_asset(safe_str(item.get("asset")))

        date_start = normalize_timestamp(safe_str(item.get("date_start")))
        date_end = normalize_timestamp(safe_str(item.get("date_end")))

        conn.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id, protocol, username, asset, asset_ip,
                system_user, login_from, date_start, date_end,
                duration, is_finished, command_amount)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                safe_str(item.get("protocol")),
                safe_str(item.get("user")),
                safe_str(item.get("asset")),
                asset_ip,
                safe_str(item.get("account")),
                safe_label(item.get("login_from")),
                date_start,
                date_end,
                safe_int(item.get("duration")),
                1 if is_finished_raw else 0,
                safe_int(item.get("command_amount")),
            ),
        )
        count += 1

    conn.commit()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    set_sync_time(conn, "session_last", now)

    if count:
        logger.info(f"会话记录: 采集 {count} 条")


# ===================== 敏感资产专用采集（5秒间隔） =====================
def collect_sensitive_fast(client: JumpServerV2Client, conn: sqlite3.Connection, cfg: dict):
    sensitive_ips = set(cfg.get("sensitive_assets", []))
    if not sensitive_ips:
        return

    now = datetime.now()
    init_time = get_sync_time(conn, "initialized") or now.strftime("%Y-%m-%d %H:%M:%S")

    # --- 1. 拉最新会话 ---
    for item in client.paginate("terminal/sessions/", {"limit": 20}):
        asset_ip = safe_str(item.get("asset_ip"))
        if not asset_ip:
            asset_ip = extract_ip_from_asset(safe_str(item.get("asset")))

        if asset_ip not in sensitive_ips:
            continue

        session_id = safe_str(item.get("id"))
        is_finished_raw = item.get("is_finished")
        if isinstance(is_finished_raw, dict):
            is_finished_raw = is_finished_raw.get("value", False)

        date_start = normalize_timestamp(safe_str(item.get("date_start")))
        date_end = normalize_timestamp(safe_str(item.get("date_end")))
        username = safe_str(item.get("user"))
        asset_name = safe_str(item.get("asset"))

        conn.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id, protocol, username, asset, asset_ip,
                system_user, login_from, date_start, date_end,
                duration, is_finished, command_amount)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                safe_str(item.get("protocol")),
                username, asset_name, asset_ip,
                safe_str(item.get("account")),
                safe_label(item.get("login_from")),
                date_start, date_end,
                safe_int(item.get("duration")),
                1 if is_finished_raw else 0,
                safe_int(item.get("command_amount")),
            ),
        )

        existing = conn.execute(
            "SELECT 1 FROM sensitive_session_tracking WHERE session_id=?",
            (session_id,),
        ).fetchone()

        if not existing:
            conn.execute(
                """INSERT INTO sensitive_session_tracking
                   (session_id, username, asset, asset_ip, protocol, date_start)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (session_id, username, asset_name, asset_ip,
                 safe_str(item.get("protocol")), date_start),
            )

            # 只对启动时间之后的会话告警，历史会话跳过
            if date_start and date_start >= init_time:
                msg = (
                    f"**用户**: {username}\n"
                    f"**资产**: {asset_name}\n"
                    f"**IP**: {asset_ip}\n"
                    f"**协议**: {item.get('protocol')}\n"
                    f"**系统用户**: {safe_str(item.get('account'))}\n"
                    f"**登录来源**: {safe_label(item.get('login_from'))}\n"
                    f"**时间**: {date_start}"
                )
                send_alert(cfg, "🔒 敏感资产登录告警", msg)
                logger.warning(f"[敏感资产] 新会话: {username} → {asset_ip} ({session_id[:8]})")
            else:
                logger.info(f"[敏感资产] 历史会话跳过告警: {username} → {asset_ip} ({date_start})")

    conn.commit()

    # --- 2. 按 session_id 拉命令 ---
    sensitive_sessions = conn.execute("""
        SELECT s.session_id, s.username, s.asset_ip
        FROM sessions s
        WHERE s.asset_ip IN ({})
          AND s.date_start >= ?
    """.format(",".join("?" * len(sensitive_ips))),
        list(sensitive_ips) + [init_time]
    ).fetchall()

    for session_id, username, asset_ip in sensitive_sessions:
        existing_cmd_count = conn.execute(
            "SELECT COUNT(*) FROM command_records WHERE session_id=?",
            (session_id,)
        ).fetchone()[0]

        if existing_cmd_count > 0:
            continue

        count = collect_commands_by_session(client, conn, cfg, session_id)
        if count:
            logger.info(f"[敏感资产] 采集命令: {username}@{asset_ip} 会话{session_id[:8]} {count}条")

    conn.commit()

    # --- 3. 已结束会话 → 命令汇总报告 ---
    rows = conn.execute("""
        SELECT t.session_id, t.username, t.asset, t.asset_ip,
               t.protocol, t.date_start, s.is_finished, s.date_end
        FROM sensitive_session_tracking t
        LEFT JOIN sessions s ON t.session_id = s.session_id
        WHERE t.commands_reported = 0
          AND s.is_finished = 1
          AND t.date_start >= ?
    """, (init_time,)).fetchall()

    for session_id, username, asset, asset_ip, protocol, date_start, \
            is_finished, date_end in rows:

        collect_commands_by_session(client, conn, cfg, session_id)

        cmd_rows = conn.execute("""
            SELECT command, timestamp, risk_level
            FROM command_records WHERE session_id = ?
            ORDER BY timestamp
        """, (session_id,)).fetchall()

        if cmd_rows:
            cmd_lines = []
            for i, (cmd, ts, risk) in enumerate(cmd_rows[:50], 1):
                risk_tag = " 🚨" if risk >= 2 else (" ⚠️" if risk >= 1 else "")
                cmd_lines.append(f"{i}. `{cmd}`{risk_tag}  ({ts})")
            cmd_text = "\n".join(cmd_lines)
            if len(cmd_rows) > 50:
                cmd_text += f"\n... 共 {len(cmd_rows)} 条，仅显示前50条"
        else:
            cmd_text = "暂无命令记录"

        msg = (
            f"**用户**: {username}\n"
            f"**资产**: {asset}\n"
            f"**IP**: {asset_ip}\n"
            f"**协议**: {protocol}\n"
            f"**开始时间**: {date_start or '—'}\n"
            f"**结束时间**: {date_end or '—'}\n"
            f"**命令数量**: {len(cmd_rows)} 条\n\n"
            f"---\n\n{cmd_text}"
        )
        send_alert(cfg, "📋 敏感资产会话结束报告", msg)
        logger.info(f"[敏感资产] 会话结束: {username}@{asset_ip} 会话{session_id[:8]} 命令{len(cmd_rows)}条")

        conn.execute(
            "UPDATE sensitive_session_tracking SET commands_reported=1 WHERE session_id=?",
            (session_id,),
        )

    conn.commit()


# ===================== 敏感资产线程 =====================
def sensitive_asset_thread_func(client_factory, conn, cfg, stop_event):
    client = client_factory()

    logger.info("[敏感资产线程] 启动，间隔 5 秒")
    while not stop_event.is_set():
        try:
            collect_sensitive_fast(client, conn, cfg)
        except requests.exceptions.ConnectionError:
            logger.error("[敏感资产线程] 连接失败，10秒后重试")
            stop_event.wait(10)
            continue
        except Exception as e:
            logger.error(f"[敏感资产线程] 异常: {e}", exc_info=True)

        stop_event.wait(5)

    logger.info("[敏感资产线程] 已停止")


# ===================== 统计摘要 =====================
def print_summary(conn: sqlite3.Connection):
    today = datetime.now().strftime("%Y-%m-%d")

    r1 = conn.execute(
        "SELECT COUNT(*) FROM login_logs WHERE timestamp >= ?", (today,)
    ).fetchone()
    r2 = conn.execute(
        "SELECT COUNT(*) FROM login_logs WHERE status='failed' AND timestamp >= ?", (today,)
    ).fetchone()
    r3 = conn.execute(
        "SELECT COUNT(*) FROM command_records WHERE timestamp >= ?", (today,)
    ).fetchone()
    r4 = conn.execute(
        "SELECT COUNT(*) FROM command_records WHERE risk_level >= 2 AND timestamp >= ?", (today,)
    ).fetchone()
    r5 = conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE date_start >= ?", (today,)
    ).fetchone()

    logger.info(
        f"📊 今日统计 | 登录: {r1[0]} (失败:{r2[0]}) "
        f"| 命令: {r3[0]} (高危:{r4[0]}) "
        f"| 会话: {r5[0]}"
    )


# ===================== 主入口 =====================
def main():
    cfg = CONFIG

    logger.info("=" * 60)
    logger.info("JumpServer v2.x 审计采集服务（增强版）")
    logger.info(f"目标: {cfg['jumpserver_url']}")
    logger.info(f"常规采集间隔: {cfg['interval']}秒")
    logger.info(f"敏感资产间隔: 5秒")
    logger.info(f"数据保留: {cfg['data_retention_days']}天")

    alert_channels = []
    if cfg.get("alert_feishu_webhook"):
        alert_channels.append("飞书")
    if cfg.get("alert_dingtalk_webhook"):
        alert_channels.append("钉钉")
    if cfg.get("alert_wechat_webhook"):
        alert_channels.append("企业微信")
    logger.info(f"告警通道: {', '.join(alert_channels) if alert_channels else '未配置'}")

    sensitive = cfg.get("sensitive_assets", [])
    logger.info(f"敏感资产: {sensitive if sensitive else '未配置'}")
    logger.info("=" * 60)

    db = init_db(cfg["db_path"])
    client = JumpServerV2Client(cfg["jumpserver_url"], cfg["username"], cfg["password"])

    stop_event = threading.Event()

    def stop(sig, frame):
        stop_event.set()
        logger.info("收到退出信号，正在停止 ...")

    try:
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
    except (OSError, ValueError):
        signal.signal(signal.SIGINT, stop)

    try:
        client._login()
    except Exception as e:
        logger.error(f"登录失败: {e}")
        return

    # 首次运行：只记录当前时间作为起点
    if not get_sync_time(db, "initialized"):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        set_sync_time(db, "login_last", now_str)
        set_sync_time(db, "command_last", now_str)
        set_sync_time(db, "session_last", now_str)
        set_sync_time(db, "initialized", now_str)
        logger.info(f"首次运行，起点时间: {now_str}（只采集此时间之后的数据）")

    # 启动敏感资产线程
    if sensitive:
        def client_factory():
            c = JumpServerV2Client(cfg["jumpserver_url"], cfg["username"], cfg["password"])
            c._login()
            return c

        t = threading.Thread(
            target=sensitive_asset_thread_func,
            args=(client_factory, db, cfg, stop_event),
            daemon=True,
        )
        t.start()
        logger.info(f"敏感资产监控线程已启动 | 监控: {sensitive}")
    else:
        logger.info("未配置敏感资产，跳过敏感监控线程")

    # 主循环
    last_cleanup = None

    while not stop_event.is_set():
        try:
            logger.info("--- 开始常规采集 ---")

            collect_login_logs(client, db, cfg)
            collect_commands(client, db, cfg)
            collect_sessions(client, db, cfg)

            check_login_failures(db, cfg)

            print_summary(db)

            today_str = datetime.now().strftime("%Y-%m-%d")
            if last_cleanup != today_str:
                cleanup_old_data(db, cfg)
                last_cleanup = today_str

            logger.info(f"--- 常规采集完成，等待 {cfg['interval']}秒 ---\n")

        except requests.exceptions.ConnectionError:
            logger.error("连接 JumpServer 失败，60秒后重试")
            stop_event.wait(60)
            continue
        except Exception as e:
            logger.error(f"采集异常: {e}", exc_info=True)

        stop_event.wait(cfg["interval"])

    db.close()
    logger.info("采集服务已停止")


if __name__ == "__main__":
    main()
