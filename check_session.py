# debug_sensitive.py
import requests
import json

BASE_URL = "http://jumpserver.example.com"
USERNAME = "admin"
PASSWORD = "Abc123456&"   # 改成你的
SENSITIVE_IP = "192.168.200.100"
FEISHU_WEBHOOK = "https://open.feishu.cn/********"        # 填你的飞书 webhook 地址

# ---- 1. 登录 ----
print("=" * 60)
print("1. 登录 JumpServer")
resp = requests.post(
    f"{BASE_URL}/api/v1/authentication/tokens/",
    json={"username": USERNAME, "password": PASSWORD},
    timeout=15,
)
token = resp.json()["token"]
print(f"   Token: {token[:20]}...")

headers = {"Authorization": f"Bearer {token}"}

# ---- 2. 查看所有会话，找敏感资产 ----
print(f"\n{'=' * 60}")
print(f"2. 查找包含 {SENSITIVE_IP} 的会话记录")

resp = requests.get(
    f"{BASE_URL}/api/v1/terminal/sessions/",
    headers=headers,
    params={"limit": 50, "offset": 0},
    timeout=30,
)
data = resp.json()
sessions = data.get("results", [])
print(f"   总会话数: {data.get('count', 0)}")
print(f"   本次拉取: {len(sessions)} 条")

found_sessions = []
for s in sessions:
    asset_ip = s.get("asset_ip", "")
    if isinstance(asset_ip, dict):
        asset_ip = asset_ip.get("value", "")
    asset_ip = str(asset_ip)

    if SENSITIVE_IP in asset_ip or asset_ip in SENSITIVE_IP:
        found_sessions.append(s)
        print(f"\n   ✅ 找到匹配会话!")
        print(f"      session_id : {s.get('id')}")
        print(f"      user       : {s.get('user')}")
        print(f"      asset      : {s.get('asset')}")
        print(f"      asset_ip   : {asset_ip}")
        print(f"      protocol   : {s.get('protocol')}")
        print(f"      date_start : {s.get('date_start')}")
        print(f"      is_finished: {s.get('is_finished')}")
        print(f"      全部字段: {json.dumps(s, indent=2, ensure_ascii=False)}")

if not found_sessions:
    print(f"\n   ❌ 在最近 50 条会话中没有找到 {SENSITIVE_IP}")
    print(f"\n   打印所有会话的 asset_ip 供核对:")
    for s in sessions[:20]:
        ip = s.get("asset_ip", "")
        if isinstance(ip, dict):
            ip = ip.get("value", "")
        user = s.get("user", "")
        if isinstance(user, dict):
            user = user.get("value", "")
        print(f"      {ip:>20s} | user={user} | {s.get('date_start')}")

# ---- 3. 用 asset 参数过滤试试 ----
print(f"\n{'=' * 60}")
print(f"3. 用 asset 参数={SENSITIVE_IP} 过滤会话")
resp = requests.get(
    f"{BASE_URL}/api/v1/terminal/sessions/",
    headers=headers,
    params={"asset": SENSITIVE_IP, "limit": 10},
    timeout=30,
)
print(f"   状态码: {resp.status_code}")
print(f"   匹配数: {resp.json().get('count', 0)}")
if resp.json().get("results"):
    for s in resp.json()["results"][:3]:
        print(f"   → {s.get('user')} | {s.get('asset_ip')} | {s.get('date_start')}")

# ---- 4. 看一下最近的命令记录 ----
print(f"\n{'=' * 60}")
print(f"4. 最近 50 条命令记录中是否有 {SENSITIVE_IP}")
resp = requests.get(
    f"{BASE_URL}/api/v1/terminal/commands/",
    headers=headers,
    params={"limit": 50},
    timeout=30,
)
cmds = resp.json().get("results", [])
print(f"   总命令数: {resp.json().get('count', 0)}")
print(f"   本次拉取: {len(cmds)} 条")

found_cmds = []
for c in cmds:
    cmd_ip = c.get("asset_ip", "")
    if isinstance(cmd_ip, dict):
        cmd_ip = cmd_ip.get("value", "")
    cmd_ip = str(cmd_ip)

    if SENSITIVE_IP in cmd_ip or cmd_ip in SENSITIVE_IP:
        found_cmds.append(c)

if found_cmds:
    print(f"   ✅ 找到 {len(found_cmds)} 条匹配命令:")
    for c in found_cmds[:5]:
        print(f"      → {c.get('user')}@{c.get('asset_ip')} | {c.get('input')}")
else:
    print(f"   ❌ 未找到匹配命令")
    print(f"   所有命令的 asset_ip:")
    for c in cmds[:20]:
        ip = c.get("asset_ip", "")
        if isinstance(ip, dict):
            ip = ip.get("value", "")
        print(f"      {str(ip):>20s} | {c.get('input', '')[:40]}")

# ---- 5. 测试飞书 Webhook ----
print(f"\n{'=' * 60}")
print(f"5. 测试飞书 Webhook")
if not FEISHU_WEBHOOK:
    print("   ⏭️  未配置飞书 webhook，跳过")
else:
    payload = {
        "msg_type": "interactive",
        "card": {
            "config": {"wide_screen_mode": True},
            "header": {
                "title": {"content": "🔍 诊断测试消息", "tag": "plain_text"},
                "template": "blue",
            },
            "elements": [
                {
                    "tag": "div",
                    "text": {
                        "content": f"**敏感资产**: {SENSITIVE_IP}\n这是一条诊断测试消息，如果你能看到说明飞书 Webhook 正常。",
                        "tag": "lark_md",
                    },
                }
            ],
        },
    }
    resp = requests.post(FEISHU_WEBHOOK, json=payload, timeout=10)
    print(f"   状态码: {resp.status_code}")
    print(f"   响应: {resp.text[:200]}")

print(f"\n{'=' * 60}")
print("诊断完成")
