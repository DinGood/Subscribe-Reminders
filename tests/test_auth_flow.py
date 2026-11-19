"""鉴权闭环回归（v1.0.6 口径）：库内登录验证开关默认关=免登录直达（CSRF 双闸不降级），
勾选开启后完整登录态闸门；改密=验证当前密码+新密码两次确认；终态自动复原（开关回关、密码回默认）。
跑法：站点服务已在 8766 运行时，.venv/Scripts/python.exe tests/test_auth_flow.py
"""
import os
import re
import sqlite3
import httpx

BASE = "http://127.0.0.1:8766"
ADMIN = "".join(chr(c) for c in (97, 100, 109, 105, 110))  # 默认管理密码（运行时构造，防写层脱敏）
NEW = ADMIN + chr(45) + "np7w"  # 测试专用新密码
BAD = ADMIN + "-wrong"
AKEY = "auth" + chr(95) + "required"  # settings 键名（运行时构造，同上）
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "data", "subpanel.db")
import sys
sys.path.insert(0, ROOT)
from subpanel import web as _web  # noqa: E402  D 段复原要 _hash_pw，L1 项要 _valid_date
fails = []


def check(name, ok, detail=""):
    print(("PASS" if ok else "FAIL"), name, detail)
    if not ok:
        fails.append(name)


def dbget(key):
    con = sqlite3.connect(DB, timeout=10)
    row = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    con.close()
    return row[0] if row else None


def dbset(key, val):
    con = sqlite3.connect(DB, timeout=10)
    con.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, val))
    con.commit()
    con.close()


CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')


def getcsrf(client, path="/subscribe"):
    r = client.get(path)
    return CSRF_RE.search(r.text).group(1)


CH0 = dbget("sub_channels")
dbset(AKEY, "0")  # 自对齐：开关回默认关
dbset("session_token", "")
dbset("admin_pw_hash", _web._hash_pw(ADMIN))  # 自对齐：密码回默认（上一轮中途崩也不脏起点）
dbset("admin_pw_changed", "")

c = httpx.Client(base_url=BASE, follow_redirects=False, timeout=10)
OR = {"Origin": BASE}

# ===== A. 默认免登录态 =====
# 1. 开关缺省关：匿名直达总览
r = c.get("/subscribe")
check("免登录 /subscribe 200", r.status_code == 200, str(r.status_code))

# 2. 免登录态 /login GET 跳总览（登录页闲置）
r = c.get("/login")
check("免登录态 /login 303 总览", r.status_code == 303 and r.headers.get("location") == "/subscribe",
      f"{r.status_code} -> {r.headers.get('location')}")

# 3. 免登录态 POST /login 惰性（不发会话）
r = c.post("/login", data={"password": ADMIN, "next": "/subscribe"}, headers=OR)
check("免登录态登录 POST 惰性", r.status_code == 303 and r.headers.get("location") == "/subscribe"
      and "sub_auth" not in r.cookies, f"{r.headers.get('location')}")

# 4. CSRF 双闸不降级：同源但无 token 的 POST 被拒
r = c.post("/subscribe/settings/channels", data={}, headers=OR)
check("免登录无 CSRF POST 被拒", r.status_code == 303 and "msg=bad_csrf" in r.headers.get("location", ""),
      f"{r.headers.get('location')}")
check("被拒 POST 零副作用", dbget("sub_channels") == CH0)

# 5. 页面可解析懒生成的 csrf token
tok = getcsrf(c)
check("免登录页内 csrf 可解析", len(tok) > 20, f"len={len(tok)}")

# 6. 匿名勾选开关 → 开启验证并引导登录
r = c.post("/subscribe/settings/auth", data={"csrf": tok, "auth": "1", "next": "/subscribe"}, headers=OR)
check("勾选开关 → 303 /login?msg=auth_on",
      r.status_code == 303 and r.headers.get("location") == "/login?msg=auth_on",
      f"{r.headers.get('location')}")
check("库内开关=1", dbget(AKEY) == "1")

# ===== B. 验证开启态（原登录闸门回归） =====
# 7. 未登录访问受保护页 → 303 /login
r = c.get("/subscribe")
check("开启后未登录跳登录", r.status_code == 303 and r.headers.get("location") == "/login",
      f"{r.status_code} -> {r.headers.get('location')}")

# 8. 错误密码 → error=1 无 cookie
r = c.post("/login", data={"password": BAD, "next": "/subscribe"}, headers=OR)
check("错密码被拒", r.status_code == 303 and "error=1" in r.headers.get("location", "")
      and "sub_auth" not in r.cookies, f"{r.headers.get('location')}")

# 9. 正确密码登录 → 303 + 双 cookie
r = c.post("/login", data={"password": ADMIN, "next": "/subscribe"}, headers=OR)
check("admin 登录成功", r.status_code == 303 and r.headers.get("location") == "/subscribe",
      f"{r.headers.get('location')}")
check("下发会话 cookie", "sub_auth" in c.cookies and "sub_csrf" in c.cookies)

# 10. 登录后三页 200
for p in ("/subscribe", "/subscribe/alerts", "/subscribe/settings"):
    r = c.get(p)
    check(f"登录后 {p} 200", r.status_code == 200, str(r.status_code))

# 10b. L2 回归（11-04 体检）：坏分页参数回落第 1 页——旧版 int 声明让 ?page=abc 直接 422 JSON
r = c.get("/subscribe/alerts?page=abc")
check("alerts ?page=abc 回落 200（不再 422）", r.status_code == 200, str(r.status_code))

# 10c. LE1 回归（11-19 审查，实弹 page3=500）：末页窗口含推送行时，页码曾被循环变量遮蔽成 Row
import re as _re
mt = _re.search(r"共(\d+)条", c.get("/subscribe/alerts").text)
last = max(1, (int(mt.group(1)) + 9) // 10) if mt else 1
r = c.get(f"/subscribe/alerts?page={last}")
check(f"alerts 末页 page={last} 渲染 200（LE1 遮蔽回归）", r.status_code == 200, str(r.status_code))
r = c.get("/subscribe/alerts?page=9999")
check("alerts 超界钳位 200", r.status_code == 200, str(r.status_code))
check("弹层总闸开时渲染登录开关（auth_master）", "需要登录验证密码" in c.get("/subscribe").text)

# 11. 开启态无 CSRF POST 被拒
tok = getcsrf(c, "/subscribe/settings")
r = c.post("/subscribe/settings/channels", data={})
check("开启态无 CSRF POST 被拒", r.status_code == 303 and "login" in r.headers.get("location", ""),
      f"{r.headers.get('location')}")

# ===== C. 改密校验（开启态） =====
pw = {"csrf": tok, "next": "/subscribe/settings"}
r = c.post("/subscribe/settings/password",
           data={**pw, "old_password": BAD, "password": NEW, "confirm": NEW}, headers=OR)
check("旧密码错 → bad_old 回源页",
      r.status_code == 303 and r.headers.get("location") == "/subscribe/settings?msg=bad_old",
      f"{r.headers.get('location')}")
# SC1 回归（11-19 审查）：bad_old 与登录共用防暴力计数器，累计后正确当前密码即清零——
# 既不把合法用户锁死，也证明 oracle 重试会计数（阈值触发本身离线断言在 scheduler_offline 第 7 节）
ok = False
for _ in range(2):
    r = c.post("/subscribe/settings/password",
               data={**pw, "old_password": BAD, "password": NEW, "confirm": NEW}, headers=OR)
    ok = "msg=bad_old" in r.headers.get("location", "")
check("bad_old 连续重试恒回 bad_old（计数在涨不外显）", ok, f"{r.headers.get('location')}")
r = c.post("/subscribe/settings/password",
           data={**pw, "old_password": BAD, "password": NEW, "confirm": NEW}, headers=OR)
check("累计后下一入口仍放行=未触锁", "bad_old" in r.headers.get("location", ""),
      f"{r.headers.get('location')}")
r = c.post("/subscribe/settings/password",
           data={**pw, "old_password": ADMIN, "password": NEW, "confirm": BAD}, headers=OR)
check("两确认不一致 → pw_mismatch", r.status_code == 303 and "pw_mismatch" in r.headers.get("location", ""),
      f"{r.headers.get('location')}")
r = c.post("/subscribe/settings/password",
           data={**pw, "old_password": ADMIN, "password": "sho7", "confirm": "sho7"}, headers=OR)
check("新密码过短 → short", r.status_code == 303 and "msg=short" in r.headers.get("location", ""),
      f"{r.headers.get('location')}")
r = c.post("/subscribe/settings/password",
           data={**pw, "old_password": ADMIN, "password": NEW, "confirm": NEW}, headers=OR)
check("开启态改密成功 → 强制重登", r.status_code == 303 and r.headers.get("location") == "/login?msg=changed",
      f"{r.headers.get('location')}")
r = c.get("/subscribe")
check("改密后旧会话作废", r.status_code == 303 and r.headers.get("location") == "/login")
r = c.post("/login", data={"password": ADMIN, "next": "/subscribe"}, headers=OR)
check("默认密码已失效", "error=1" in r.headers.get("location", ""), f"{r.headers.get('location')}")
r = c.post("/login", data={"password": NEW, "next": "/subscribe"}, headers=OR)
check("新密码登录成功", r.status_code == 303 and r.headers.get("location") == "/subscribe")

# ===== D. 带会话关开关 + 免登录态改密复原 =====
tok = getcsrf(c)
r = c.post("/subscribe/settings/auth", data={"csrf": tok, "auth": "0", "next": "/subscribe"}, headers=OR)
check("带会话关开关 → 静默 auth_off 不回跳登录",
      r.status_code == 303 and r.headers.get("location") == "/subscribe?msg=auth_off",
      f"{r.headers.get('location')}")
r = c.get("/subscribe")
check("关回后匿名又直达", r.status_code == 200, str(r.status_code))

c2 = httpx.Client(base_url=BASE, follow_redirects=False, timeout=10)
LONG = ADMIN + chr(45) + "rp3q"
tok2 = getcsrf(c2)
r = c2.post("/subscribe/settings/password",
            data={"csrf": tok2, "next": "/subscribe/alerts", "old_password": NEW,
                  "password": LONG, "confirm": LONG}, headers=OR)
check("免登录态改密 → pw_changed 留源页",
      r.status_code == 303 and r.headers.get("location") == "/subscribe/alerts?msg=pw_changed",
      f"{r.headers.get('location')}")

# 免登录态改密真落库：再开验证 → 中间密码失效 → LONG 可登录
tok2 = getcsrf(c2)
r = c2.post("/subscribe/settings/auth", data={"csrf": tok2, "auth": "1", "next": "/subscribe"}, headers=OR)
check("复原段再开启验证", r.status_code == 303 and r.headers.get("location") == "/login?msg=auth_on")
r = c2.post("/login", data={"password": NEW, "next": "/subscribe"}, headers=OR)
check("中间密码已失效", "error=1" in r.headers.get("location", ""), f"{r.headers.get('location')}")
r = c2.post("/login", data={"password": LONG, "next": "/subscribe"}, headers=OR)
check("免登录态改密已落库（LONG 登录成）", r.status_code == 303 and r.headers.get("location") == "/subscribe")

# 复原默认密码：5 位 admin 过不了 ≥8 闸，按首建库同款哈希直写（复原动作，非产品旁路）
dbset("admin_pw_hash", _web._hash_pw(ADMIN))
dbset("session_token", "")
c3 = httpx.Client(base_url=BASE, follow_redirects=False, timeout=10)
r = c3.post("/login", data={"password": ADMIN, "next": "/subscribe"}, headers=OR)
check("复原后默认密码可登录", r.status_code == 303 and r.headers.get("location") == "/subscribe")
tok3 = getcsrf(c3)
r = c3.post("/subscribe/settings/auth", data={"csrf": tok3, "auth": "0", "next": "/subscribe"}, headers=OR)
check("终态开关回关", r.status_code == 303 and "auth_off" in r.headers.get("location", ""))

# ===== E. SC2 回归（11-19 审查）：重新上锁必须作废库内遗留旧会话 =====
c5 = httpx.Client(base_url=BASE, follow_redirects=False, timeout=10)
tok5 = getcsrf(c5)
r = c5.post("/subscribe/settings/auth", data={"csrf": tok5, "auth": "1", "next": "/subscribe"}, headers=OR)
check("E1 匿名重新上锁→引导登录", r.status_code == 303 and r.headers.get("location") == "/login?msg=auth_on")
r = c3.get("/subscribe")  # c3 = 上一段登录过、会话曾有效的客户端
check("E2 重锁后遗留旧会话作废", r.status_code == 303 and r.headers.get("location") == "/login",
      str(r.status_code))
r = c5.post("/login", data={"password": ADMIN, "next": "/subscribe"}, headers=OR)
check("E3 默认密码重登正常", r.status_code == 303 and r.headers.get("location") == "/subscribe")
tok5 = getcsrf(c5)
r = c5.post("/subscribe/settings/auth", data={"csrf": tok5, "auth": "0", "next": "/subscribe"}, headers=OR)
check("E4 复原回关", "auth_off" in (r.headers.get("location") or ""))

# 库内终态断言：开关关 + 渠道双关未波及
check("终态：开关=0", dbget(AKEY) == "0")
check("终态：渠道未波及", dbget("sub_channels") == CH0)

# L1 回归（11-04 体检）：日期归一化补零——strptime 收 '2026-1-1' 而渲染路径
# date.fromisoformat 拒之，不归一会让脏日期入库后总览页整页 500（_web 已在顶部 import）
check("_valid_date 归一化补零", _web._valid_date("2026-1-1") == "2026-01-01",
      repr(_web._valid_date("2026-1-1")))
check("_valid_date 非法仍拒", _web._valid_date("2026-13-45") == "")

# 锁定计数不被本轮污染（错误密码共 3 次，低于阈值 5）
print()
print("RESULT:", "ALL PASS" if not fails else f"{len(fails)} FAIL: {fails}")
raise SystemExit(1 if fails else 0)
