"""E2E 回归：续费网站 URL（校验/回显/链接渲染）+ 一键续期（周期推进/幂等键清除/一次性拒绝）。

跑法：本机服务拉起后 `.venv/Scripts/python.exe tests/test_sub_url_renew.py`。
测试自建临时订阅（标题带 _t 前缀），跑完自动删除，不碰存量数据。
注意：POST 必须带 Referer（CSRF 同源闸，10-08 v1.0.1 教训）。
"""
import re
import sqlite3
import sys
import urllib.request
import urllib.parse
import http.cookiejar

import os
BASE = "http://127.0.0.1:8766"
DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "subpanel.db")

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def req(path, data=None, follow=True):
    body = urllib.parse.urlencode(data).encode() if data else None
    r = urllib.request.Request(BASE + path, data=body)
    if body:
        r.add_header("Referer", BASE + "/subscribe")
    return op.open(r, timeout=10)

def csrf(page):
    return re.search(r'name="csrf" value="([^"]+)"', page.read().decode()).group(1)

results = []
def check(name, ok):
    results.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name)

# 登录
req("/login", {"password": "admin"})
page = req("/subscribe").read().decode()
check("登录后 /subscribe 200", "订阅总览" in page)

tok = csrf(req("/subscribe"))
FORM = dict(csrf=tok, sub_type="periodic", category="VPS", period="monthly",
            custom_days="30", next_date="2026-11-01", amount="1", currency="CNY", note="")

# 1) 非法 URL 拒收
r = req("/subscribe/add", {**FORM, "title": "_t_badurl", "url": "javascript:alert(1)"})
check("非法 URL 回 bad_url", "msg=bad_url" in r.geturl())

# 2) 合法 URL 入库+列表渲染 <a target=_blank>
r = req("/subscribe/add", {**FORM, "title": "_t_ok", "url": "https://example.com/pay?x=1"})
pid = sqlite3.connect(DB).execute(
    "SELECT id FROM subs WHERE title='_t_ok'").fetchone()[0]
page = req("/subscribe").read().decode()
check("合法 URL 保存并回显", f'/subscribe/{pid}/update' in page and 'href="https://example.com/pay?x=1"' in page)
m = re.search(r'<a [^>]*href="https://example\.com[^"]*"[^>]*>', page)
check("名称链接新窗口+noopener", bool(m and "target=\"_blank\"" in m.group(0) and "noopener" in m.group(0)))

# 3) 编辑更新 URL
r = req(f"/subscribe/{pid}/update", {**FORM, "title": "_t_ok", "url": "https://changed.test/"})
row = sqlite3.connect(DB).execute("SELECT url FROM subs WHERE id=?", (pid,)).fetchone()
check("update 改 URL 落库", row[0] == "https://changed.test/")

# 3b) 金额必填：add 空金额回 bad_amount（不带 sid=弹窗流）；update 空金额回 bad_amount&sid（编辑区流）
r = req("/subscribe/add", {**FORM, "title": "_t_amt0", "amount": ""})
check("add 空金额回 bad_amount 且无 sid", r.geturl().endswith("msg=bad_amount"))
r = req(f"/subscribe/{pid}/update", {**FORM, "title": "_t_ok", "amount": ""})
check("update 空金额回 bad_amount&sid", "msg=bad_amount" in r.geturl() and f"sid={pid}" in r.geturl())
amt = sqlite3.connect(DB).execute("SELECT amount FROM subs WHERE id=?", (pid,)).fetchone()[0]
check("空金额 update 被拦原值无损", amt == "1")

# 4) 一键续期：2026-11-01 月付 -> 2026-12-01
r = req(f"/subscribe/{pid}/renew", {"csrf": csrf(req("/subscribe"))})
row = sqlite3.connect(DB).execute(
    "SELECT next_date,fired FROM subs WHERE id=?", (pid,)).fetchone()
check("续期推进一期", row[0] == "2026-12-01")
check("续期清幂等键 fired", row[1] == "")

# 5) 二次续期再推进
r = req(f"/subscribe/{pid}/renew", {"csrf": csrf(req("/subscribe"))})
row = sqlite3.connect(DB).execute("SELECT next_date FROM subs WHERE id=?", (pid,)).fetchone()
check("连续续期可叠加推进", row[0] == "2027-01-01")

# 6) 一次性项拒绝续期
r = req("/subscribe/add", {**FORM, "title": "_t_once", "sub_type": "once", "url": ""})
oid = sqlite3.connect(DB).execute("SELECT id FROM subs WHERE title='_t_once'").fetchone()[0]
r = req(f"/subscribe/{oid}/renew", {"csrf": csrf(req("/subscribe"))})
check("一次性项续期被拒 bad_renew", "msg=bad_renew" in r.geturl())

# 7) 无 URL 的订阅名称不渲染链接（纯 <b>，不被 <a href> 包裹）
page = req("/subscribe").read().decode()
check("无 URL 订阅名称为纯文本", re.search(r'<b[^>]*>_t_once</b>', page) is not None
      and f'href="https://changed.test/"' in page)

# 清理临时数据
conn = sqlite3.connect(DB)
conn.execute("DELETE FROM subs WHERE title LIKE '_t_%'")
conn.execute("DELETE FROM alerts WHERE sub_id NOT IN (SELECT id FROM subs)")
conn.execute("DELETE FROM sub_pushes WHERE alert_id NOT IN (SELECT id FROM alerts)")
conn.commit()
left = conn.execute("SELECT COUNT(*) FROM subs WHERE title LIKE '_t_%'").fetchone()[0]
check("临时订阅清理", left == 0)

fails = [n for n, ok in results if not ok]
print(f"\n{len(results)} 项，失败 {len(fails)}")
sys.exit(1 if fails else 0)
