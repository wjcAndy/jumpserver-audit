# get_token_test.py
import requests

BASE_URL = "http://jumpserver.example.com"  # 改这里

# ===== 方式一：用用户名密码获取 Token =====
print(">>> 尝试用户名密码登录 ...")
resp = requests.post(
    f"{BASE_URL}/api/v1/authentication/tokens/",
    json={
        "username": "admin",   # 改这里
        "password": "Abc123456&",     # 改这里
    },
    headers={"Content-Type": "application/json"},
    timeout=10,
)
print(f"状态码: {resp.status_code}")
print(f"响应: {resp.text[:500]}")

if resp.status_code == 200:
    data = resp.json()
    token = data.get("token") or data.get("access") or data.get("key")
    print(f"\n✅ Token 获取成功!")
    print(f"Token: {token}")

    # 用 Token 测试 API
    print(f"\n>>> 用 Token 测试 API ...")
    resp2 = requests.get(
        f"{BASE_URL}/api/v1/audits/login-logs/?limit=3",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    print(f"状态码: {resp2.status_code}")
    if resp2.status_code == 200:
        print(f"✅ API 调用成功!")
        print(f"响应: {resp2.text[:500]}")
    else:
        # 有些版本用 Token 关键字
        resp3 = requests.get(
            f"{BASE_URL}/api/v1/audits/login-logs/?limit=3",
            headers={"Authorization": f"Token {token}"},
            timeout=10,
        )
        print(f"[Token] 状态码: {resp3.status_code}")
        print(f"[Token] 响应: {resp3.text[:500]}")

elif resp.status_code == 400:
    print("\n用户名密码有误，或需要其他参数格式")

# ===== 方式二：尝试 AK/SK 作为 username/password =====
print("\n>>> 尝试 AK/SK 作为凭证 ...")
resp = requests.post(
    f"{BASE_URL}/api/v1/authentication/tokens/",
    json={
        "username": "5dfb9cad-0789-4ff7-bea7-c622cffc4e94",    # 试试用 AK 当用户名
        "password": "nLEyChf9mnWAppTCv0rMRquXuMwBqBb3Senx",   # 试试用 SK 当密码
    },
    headers={"Content-Type": "application/json"},
    timeout=10,
)
print(f"状态码: {resp.status_code}")
print(f"响应: {resp.text[:500]}")

if resp.status_code == 200:
    data = resp.json()
    token = data.get("token") or data.get("access") or data.get("key")
    print(f"\n✅ AK/SK 登录成功! Token: {token}")
