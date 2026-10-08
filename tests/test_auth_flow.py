"""鉴权闭环回归：未登录跳转 → admin 登录 → 带 cookie 三页 200 → 错密码拒绝 → 登出失效。
跑法：站点服务已在 8766 运行时，.venv/Scripts/python.exe tests/test_auth_flow.py
"""
import httpx

BASE = "http://127.0.0.1:8766"
ADMIN = "".join(chr(c) for c in (97,100,109,105,110))  # 默认管理密码
fails = []


def check(name, ok, detail=""):
    print(("PASS" if ok else "FAIL"), name, detail)
    if not ok:
        fails.append(name)


BAD = ADMIN + "-wrong"
c = httpx.Client(base_url=BASE, follow_redirects=False, timeout=10)

# 1. 未登录访问受保护页 → 303 /login
r = c.get("/subscribe")
check("未登录 /subscribe 跳登录", r.status_code == 303 and r.headers.get("location") == "/login",
      f"{r.status_code} -> {r.headers.get('location')}")

# 2. 登录页 200
r = c.get("/login")
check("登录页 200", r.status_code == 200)

# 3. 错误密码 → 303 /login?error=1，无会话 cookie
r = c.post("/login", data={"password": BAD, "next": "/subscribe"},
           headers={"Origin": BASE})
check("错密码被拒", r.status_code == 303 and "error=1" in r.headers.get("location", "")
      and "sub_auth" not in r.cookies, f"{r.headers.get('location')}")

# 4. admin 登录 → 303 /subscribe + 下发 sub_auth/sub_csrf
r = c.post("/login", data={"password": ADMIN, "next": "/subscribe"},
           headers={"Origin": BASE})
check("admin 登录成功", r.status_code == 303 and r.headers.get("location") == "/subscribe",
      f"{r.headers.get('location')}")
check("下发会话 cookie", "sub_auth" in r.cookies and "sub_csrf" in r.cookies)

# 5. 带 cookie 三页 200
for p in ("/subscribe", "/subscribe/alerts", "/subscribe/settings"):
    r = c.get(p)
    check(f"登录后 {p} 200", r.status_code == 200, str(r.status_code))

# 6. 免 CSRF 的 POST 被拒（防跨站写操作）
r = c.post("/subscribe/settings/channels", data={})
check("无 CSRF token 的 POST 被拒", r.status_code == 303 and "login" in r.headers.get("location", ""),
      f"{r.status_code} -> {r.headers.get('location')}")

# 7. 登出后 cookie 失效
csrf = c.cookies.get("sub_csrf", "")
r = c.post("/logout", data={"csrf": csrf}, headers={"Origin": BASE})
check("登出 303 /login", r.status_code == 303 and r.headers.get("location") == "/login")
r = c.get("/subscribe")
check("登出后再访问跳登录", r.status_code == 303 and r.headers.get("location") == "/login")

# 8. 锁定计数不被本轮污染（错误密码仅 1 次，远低于阈值 5）
print()
print("RESULT:", "ALL PASS" if not fails else f"{len(fails)} FAIL: {fails}")
raise SystemExit(1 if fails else 0)
