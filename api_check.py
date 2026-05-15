# 测试api联通性
import requests

BASE_URL = "http://jumpserver.example.com"
AK = ""
SK = ""

# ========== 第一步：确认能访问 ==========
print("=" * 60)
print("第一步：测试基础连通性")
print("=" * 60)

try:
    resp = requests.get(f"{BASE_URL}/api/v1/", timeout=10)
    print(f"  /api/v1/ → {resp.status_code}")
    if resp.status_code == 200:
        print(f"  内容: {resp.text[:300]}")
except Exception as e:
    print(f"  连接失败: {e}")

# ========== 第二步：探测认证接口 ==========
print("\n" + "=" * 60)
print("第二步：探测认证接口（逐个尝试）")
print("=" * 60)

auth_endpoints = [
    # v3.x 常见路径
    "/api/v1/authentication/auth/token/",
    "/api/v1/authentication/v2/auth/token/",
    "/api/v1/authentication/tokens/",
    "/api/v1/auth/token/",
    # v2.x 常见路径
    "/api/v1/users/token/",
    "/api/users/v1/token/",
    "/api/v1/authentication/token/",
    # 不带 v1
    "/api/authentication/auth/token/",
    "/api/authentication/token/",
    "/api/token/",
    # core token 接口
    "/api/v1/core/auth/token/",
]

for ep in auth_endpoints:
    url = f"{BASE_URL}{ep}"
    try:
        resp = requests.post(
            url,
            json={"access_key": AK, "secret_key": SK},
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        status = resp.status_code
        body = resp.text[:200]
        marker = "✅ 找到了！" if status == 200 else ("⚠️  有响应" if status in (400, 401, 403) else "❌")
        print(f"  [{status}] {ep}  {marker}")
        if status in (200, 400, 401, 403):
            print(f"       响应: {body}")
    except Exception as e:
        print(f"  [ERR] {ep} → {e}")

# ========== 第三步：尝试 AK/SK 作为 Bearer 直接用 ==========
print("\n" + "=" * 60)
print("第三步：直接用 AK 当 Token 测试 API")
print("=" * 60)

test_apis = [
    "/api/v1/audits/login-logs/?limit=1",
    "/api/v1/terminal/commands/?limit=1",
    "/api/v1/terminal/sessions/?limit=1",
    "/api/v1/users/users/?limit=1",
    "/api/v1/assets/assets/?limit=1",
]

for api in test_apis:
    url = f"{BASE_URL}{api}"
    # 尝试方式 A: Bearer ak
    try:
        resp = requests.get(url, headers={"Authorization": f"Bearer {AK}"}, timeout=5)
        marker = "✅" if resp.status_code == 200 else ""
        print(f"  [Bearer AK] [{resp.status_code}] {api}  {marker}")
        if resp.status_code == 200:
            print(f"       {resp.text[:200]}")
    except Exception as e:
        print(f"  [Bearer AK] [ERR] {api} → {e}")

    # 尝试方式 B: Token ak
    try:
        resp = requests.get(url, headers={"Authorization": f"Token {AK}"}, timeout=5)
        marker = "✅" if resp.status_code == 200 else ""
        print(f"  [Token AK]  [{resp.status_code}] {api}  {marker}")
        if resp.status_code == 200:
            print(f"       {resp.text[:200]}")
    except Exception as e:
        print(f"  [Token AK]  [ERR] {api} → {e}")

# ========== 第四步：尝试 Django REST Framework Token Auth ==========
print("\n" + "=" * 60)
print("第四步：尝试 v2.x HMAC 签名认证")
print("=" * 60)

import hashlib, hmac, base64
from datetime import datetime, timezone

try:
    now = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    method = "GET"
    path = "/api/v1/audits/login-logs/"

    string_to_sign = f"{method}\n\n\n{now}\n{path}"
    signature = base64.b64encode(
        hmac.new(SK.encode(), string_to_sign.encode(), hashlib.sha1).digest()
    ).decode()

    auth_header = f"jms {AK}:{signature}"

    resp = requests.get(
        f"{BASE_URL}{path}",
        headers={
            "Authorization": auth_header,
            "Date": now,
        },
        params={"limit": 1},
        timeout=5,
    )
    print(f"  HMAC 签名 → [{resp.status_code}]")
    if resp.status_code == 200:
        print(f"  ✅ HMAC 签名认证成功!")
        print(f"  {resp.text[:300]}")
    else:
        print(f"  响应: {resp.text[:200]}")
except Exception as e:
    print(f"  HMAC 签名失败: {e}")

# ========== 第五步：尝试获取版本信息 ==========
print("\n" + "=" * 60)
print("第五步：获取 JumpServer 版本")
print("=" * 60)

version_apis = [
    "/api/v1/settings/public/",
    "/api/v1/public-settings/",
    "/api/settings/v1/public/",
]
for api in version_apis:
    try:
        resp = requests.get(f"{BASE_URL}{api}", timeout=5)
        print(f"  [{resp.status_code}] {api}")
        if resp.status_code == 200:
            print(f"       {resp.text[:300]}")
    except Exception as e:
        print(f"  [ERR] {api} → {e}")

# 从网页获取版本
try:
    resp = requests.get(f"{BASE_URL}/", timeout=5)
    if "jumpserver" in resp.text.lower():
        # 尝试从 HTML 中提取版本号
        import re
        ver = re.search(r'v(\d+\.\d+[\.\d]*)', resp.text)
        if ver:
            print(f"  网页中发现版本号: v{ver.group(1)}")
except:
    pass

print("\n" + "=" * 60)
print("诊断完成，请把以上输出发给我，我帮你改代码")
print("=" * 60)
