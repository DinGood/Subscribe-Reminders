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
# 日期防时炸（10-04 写死 2026-11-01，11 月后过期被调度补扫即时推进，断言必炸）：
# 一律取「下月/下下月/下三月 1 号」相对值，月付 advance 恰好逐级 +1 月
from datetime import date as _dt
def _m1(n):
    y, m = _dt.today().year, _dt.today().month + n
    y += (m - 1) // 12; m = (m - 1) % 12 + 1
    return _dt(y, m, 1).isoformat()
ND0, ND1, ND2 = _m1(1), _m1(2), _m1(3)
FORM = dict(csrf=tok, sub_type="periodic", category="VPS", period="monthly",
            custom_days="30", next_date=ND0, amount="1", currency="CNY", note="")

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

# 4) 一键续期：ND0 月付 -> ND1（下月 1 号）
r = req(f"/subscribe/{pid}/renew", {"csrf": csrf(req("/subscribe"))})
row = sqlite3.connect(DB).execute(
    "SELECT next_date,fired FROM subs WHERE id=?", (pid,)).fetchone()
check("续期推进一期", row[0] == ND1)
check("续期清幂等键 fired", row[1] == "")

# 5) 二次续期再推进
r = req(f"/subscribe/{pid}/renew", {"csrf": csrf(req("/subscribe"))})
row = sqlite3.connect(DB).execute("SELECT next_date FROM subs WHERE id=?", (pid,)).fetchone()
check("连续续期可叠加推进", row[0] == ND2)

# 6) 一次性项拒绝续期
r = req("/subscribe/add", {**FORM, "title": "_t_once", "sub_type": "once", "url": ""})
oid = sqlite3.connect(DB).execute("SELECT id FROM subs WHERE title='_t_once'").fetchone()[0]
r = req(f"/subscribe/{oid}/renew", {"csrf": csrf(req("/subscribe"))})
check("一次性项续期被拒 bad_renew", "msg=bad_renew" in r.geturl())
# 3c) M1 回归（11-04 体检）：非排期字段编辑不清幂等键（防已送达提醒复位重发）；排期变化才清
# 直写库必须短连接+busy timeout——长挂连接在 WAL 下与服务写入相撞（11-04 实测 database is locked）
def _dbw(sql, args=()):
    con = sqlite3.connect(DB, timeout=15)
    try:
        con.execute(sql, args); con.commit()
    finally:
        con.close()
def _nbr(sql, args=()):
    con = sqlite3.connect(DB, timeout=15)
    try:
        return con.execute(sql, args).fetchone()
    finally:
        con.close()
_dbw("UPDATE subs SET fired='2026-01-01:0' WHERE id=?", (pid,))
# 注意：此段现跑在 4)/5) 两次续期之后，行的排期已非 FORM 初值——update 必须带行的**当前**排期，
# 否则等于真的改期（产品清 fired 是正确行为），断言就变成测顺序而非测 M1（11-04 首跑 FAIL 的根因）
_now = _nbr("SELECT next_date,period,custom_days FROM subs WHERE id=?", (pid,))
r = req(f"/subscribe/{pid}/update", {**FORM, "title": "_t_ok", "url": "https://changed.test/",
                                     "note": "只改备注", "next_date": _now[0], "period": _now[1],
                                     "custom_days": str(_now[2] or 0)})
f1 = _nbr("SELECT fired FROM subs WHERE id=?", (pid,))[0]
check("M1 备注类编辑保留 fired 幂等键", f1 == "2026-01-01:0")
r = req(f"/subscribe/{pid}/update", {**FORM, "title": "_t_ok", "url": "https://changed.test/",
                                     "next_date": _m1(5), "period": _now[1],
                                     "custom_days": str(_now[2] or 0)})
row = _nbr("SELECT fired,next_date FROM subs WHERE id=?", (pid,))
check("M1 改期编辑清 fired 并复活", row[0] == "" and row[1] == _m1(5))

# 3d) LE2 回归（11-19 审查）：浏览器省略整个 disabled custom_days 字段（表单不含该键）时，
# Form 默认 "30" 不得把 custom_days=0 的月付老行误判改期——fired 必须原样保留
_dbw("UPDATE subs SET fired='2026-01-01:0',custom_days=0 WHERE id=?", (pid,))
_now = _nbr("SELECT next_date,period FROM subs WHERE id=?", (pid,))
_body = {k: v for k, v in FORM.items() if k != "custom_days"}
r = req(f"/subscribe/{pid}/update", {**_body, "title": "_t_ok", "url": "https://changed.test/",
                                     "note": "只改备注", "next_date": _now[0], "period": _now[1]})
f1 = _nbr("SELECT fired FROM subs WHERE id=?", (pid,))[0]
check("LE2 缺省 custom_days 字段不误判改期", f1 == "2026-01-01:0")
_dbw("UPDATE subs SET fired='' WHERE id=?", (pid,))  # 复位，别把伪造键留给清理段



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
