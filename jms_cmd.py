# debug_commands.py
import requests
import json
import sqlite3

BASE_URL = "http://jumpserver.example.com"
USERNAME = "admin"
PASSWORD = "Abc123456&"
DB_PATH = "./jumpserver_audit.db"
SENSITIVE_IP = "192.168.200.100"

# ---- 1. 从数据库取最近的敏感资产会话 ----
print("=" * 60)
print("1. 从数据库查找最近的敏感资产会话")
conn = sqlite3.connect(DB_PATH)
rows = conn.execute("""
    SELECT session_id, username, asset, date_start, is_finished
    FROM sessions
    WHERE asset_ip = ?
    ORDER BY date_start DESC
    LIMIT 5
""", (SENSITIVE_IP,)).fetchall()

if not rows:
    # asset_ip 可能为空，从 asset 名称中找
    rows = conn.execute("""
        SELECT session_id, username, asset, date_start, is_finished
        FROM sessions
        WHERE asset LIKE ?
        ORDER BY date_start DESC
        LIMIT 5
    """, (f"%{SENSITIVE_IP}%",)).fetchall()

if rows:
    for r in rows:
        print(f"  session_id={r[0]} | user={r[1]} | {r[2]} | {r[3]} | finished={r[4]}")
    SESSION_ID = rows[0][0]
    print(f"\n  使用最新会话: {SESSION_ID}")
else:
    print("  ❌ 数据库中未找到敏感资产会话")
    conn.close()
    exit(1)

# ---- 2. 从数据库查该会话的命令 ----
print(f"\n{'=' * 60}")
print(f"2. 数据库中该会话的命令记录")
cmd_rows = conn.execute("""
    SELECT command, timestamp, risk_level
    FROM command_records
    WHERE session_id = ?
    ORDER BY timestamp
""", (SESSION_ID,)).fetchall()
print(f"  数据库中命令数: {len(cmd_rows)}")
for c in cmd_rows:
    print(f"  → {c[1]} | risk={c[2]} | {c[0]}")

conn.close()

# ---- 3. 登录 JumpServer ----
print(f"\n{'=' * 60}")
print("3. 登录 JumpServer")
resp = requests.post(
    f"{BASE_URL}/api/v1/authentication/tokens/",
    json={"username": USERNAME, "password": PASSWORD},
    timeout=15,
)
token = resp.json()["token"]
headers = {"Authorization": f"Bearer {token}"}
print(f"  Token: {token[:20]}...")

# ---- 4. 查看该会话详情 ----
print(f"\n{'=' * 60}")
print(f"4. 会话详情: {SESSION_ID}")
resp = requests.get(
    f"{BASE_URL}/api/v1/terminal/sessions/{SESSION_ID}/",
    headers=headers,
    timeout=30,
)
if resp.status_code == 200:
    s = resp.json()
    print(f"  user: {s.get('user')}")
    print(f"  asset: {s.get('asset')}")
    print(f"  protocol: {s.get('protocol')}")
    print(f"  command_amount: {s.get('command_amount')}")
    print(f"  has_command: {s.get('has_command')}")
    print(f"  has_replay: {s.get('has_replay')}")
    print(f"  is_finished: {s.get('is_finished')}")
    print(f"  date_start: {s.get('date_start')}")
    print(f"  date_end: {s.get('date_end')}")
else:
    print(f"  失败: {resp.status_code} {resp.text[:200]}")

# ---- 5. 最近 30 条命令的完整结构 ----
print(f"\n{'=' * 60}")
print("5. 最近 5 条命令的完整字段结构")
resp = requests.get(
    f"{BASE_URL}/api/v1/terminal/commands/",
    headers=headers,
    params={"limit": 5},
    timeout=30,
)
data = resp.json()
print(f"  总命令数: {data.get('count', 0)}")
cmds = data.get("results", [])
if cmds:
    print(f"  字段列表: {list(cmds[0].keys())}")
    for i, c in enumerate(cmds[:3]):
        print(f"\n  --- 命令 {i+1} ---")
        print(json.dumps(c, indent=2, ensure_ascii=False))
else:
    print("  ⚠️ API 返回 0 条命令！命令可能存在别的端点")

# ---- 6. 搜索所有命令中包含这个 session 的 ----
print(f"\n{'=' * 60}")
print(f"6. 在最新 200 条命令中搜索 session={SESSION_ID}")
found = []
page_size = 100
for offset in [0, 100]:
    resp = requests.get(
        f"{BASE_URL}/api/v1/terminal/commands/",
        headers=headers,
        params={"limit": page_size, "offset": offset},
        timeout=30,
    )
    for c in resp.json().get("results", []):
        cmd_session = str(c.get("session", ""))
        if SESSION_ID in cmd_session:
            found.append(c)

if found:
    print(f"  ✅ 找到 {len(found)} 条:")
    for c in found:
        print(f"    → session={c.get('session')} | user={c.get('user')} | cmd={c.get('input', c.get('command', ''))}")
else:
    print(f"  ❌ 未找到，打印所有 session 值:")
    resp = requests.get(
        f"{BASE_URL}/api/v1/terminal/commands/",
        headers=headers,
        params={"limit": 30},
        timeout=30,
    )
    for c in resp.json().get("results", [])[:15]:
        s = str(c.get("session", ""))
        cmd = c.get("input", c.get("command", ""))
        print(f"    session={s[:36]:>36s} | user={c.get('user')} | cmd={str(cmd)[:40]}")

# ---- 7. 尝试所有可能的命令端点和过滤参数 ----
print(f"\n{'=' * 60}")
print(f"7. 遍历所有可能的命令端点")

endpoints_to_try = [
    # 标准端点 + 不同过滤参数
    ("/api/v1/terminal/commands/", {"session": SESSION_ID, "limit": 10}),
    ("/api/v1/terminal/commands/", {"session_id": SESSION_ID, "limit": 10}),
    ("/api/v1/terminal/commands/", {"limit": 30}),
    # audits 端点
    ("/api/v1/audits/commands/", {"limit": 10}),
    ("/api/v1/audits/commands/", {"session": SESSION_ID, "limit": 10}),
    # session 专属端点
    (f"/api/v1/terminal/sessions/{SESSION_ID}/commands/", {"limit": 10}),
    # 不同 API 版本
    ("/api/v2/terminal/commands/", {"limit": 10}),
    ("/api/terminal/commands/", {"limit": 10}),
]

for path, params in endpoints_to_try:
    try:
        resp = requests.get(
            f"{BASE_URL}{path}",
            headers=headers,
            params=params,
            timeout=10,
        )
        s = resp.status_code
        if s == 200:
            d = resp.json()
            cnt = d.get("count", len(d) if isinstance(d, list) else "?")
            marker = "✅" if cnt and cnt != 0 else "⚠️ count=0"
            print(f"  [{s}] {path} params={params}  {marker}  count={cnt}")
            if d.get("results"):
                for r in d["results"][:2]:
                    cmd = r.get("input", r.get("command", ""))
                    print(f"       → {r.get('user')} | session={r.get('session', '?')} | cmd={str(cmd)[:50]}")
        else:
            print(f"  [{s}] {path} params={params}")
    except Exception as e:
        print(f"  [ERR] {path} → {e}")

# ---- 8. 尝试命令搜索（某些版本用 q 参数） ----
print(f"\n{'=' * 60}")
print("8. 尝试用关键词搜索命令（ip a）")
for param_name in ["q", "search", "keyword", "command"]:
    resp = requests.get(
        f"{BASE_URL}/api/v1/terminal/commands/",
        headers=headers,
        params={param_name: "ip a", "limit": 10},
        timeout=10,
    )
    if resp.status_code == 200:
        cnt = resp.json().get("count", 0)
        print(f"  参数 '{param_name}': count={cnt}")
        if cnt and cnt > 0:
            for r in resp.json().get("results", [])[:3]:
                print(f"    → {r.get('input', r.get('command', ''))}")
    else:
        print(f"  参数 '{param_name}': {resp.status_code}")

print(f"\n{'=' * 60}")
print("诊断完成，请把以上输出贴给我")
