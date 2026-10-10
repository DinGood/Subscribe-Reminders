"""LOGO SVG 支持回归：良性 SVG 入库/恶意净化/伪格式拒绝/旧格式不回归 + CSP 响应头。

跑法：本机服务拉起后 `.venv/Scripts/python.exe tests/test_logo_svg.py`。
自建临时订阅（_t_ 前缀），跑完自清理。POST 必须带 Referer（CSRF 同源闸）。
"""
import os
import re
import sys
import glob
import sqlite3
import urllib.parse
import urllib.request
import http.cookiejar

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "data", "subpanel.db")
BASE = "http://127.0.0.1:8766"
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
results = []


def check(name, ok):
    results.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name)


def req(path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    rq = urllib.request.Request(BASE + path, data=body)
    if body:
        rq.add_header("Referer", BASE + "/subscribe")
    return op.open(rq, timeout=10)


def upload_logo(pid, csrf, fname, fbytes):
    b = "----t"
    parts = (f"--{b}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{csrf}\r\n"
             f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fname}\"\r\n\r\n").encode()
    parts += fbytes + f"\r\n--{b}--\r\n".encode()
    rq = urllib.request.Request(BASE + f"/subscribe/{pid}/logo", data=parts)
    rq.add_header("Content-Type", "multipart/form-data; boundary=" + b)
    rq.add_header("Referer", BASE + "/subscribe")  # CSRF 闸：POST 必带
    return op.open(rq, timeout=10)


def sub_id(title):
    return sqlite3.connect(DB).execute(
        "SELECT id FROM subs WHERE title=?", (title,)).fetchone()[0]


req("/login", {"password": "admin"})
tok = re.search(r'name="csrf" value="([^"]+)"', req("/subscribe").read().decode()).group(1)
FORM = dict(csrf=tok, sub_type="periodic", category="VPS", period="monthly",
            custom_days="30", next_date="2026-12-01", amount="1", currency="CNY",
            note="", title="_t_svg", url="")
req("/subscribe/add", FORM)
pid = sub_id("_t_svg")

GOOD = (b'\xef\xbb\xbf<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"'
        b' viewBox="0 0 10 10"><rect width="10" height="10" fill="blue"/></svg>')
r = upload_logo(pid, tok, "a.svg", GOOD)
row = sqlite3.connect(DB).execute("SELECT has_logo,logo_ext FROM subs WHERE id=?", (pid,)).fetchone()
check("良性 SVG（含 BOM+XML 声明）入库", r.geturl().endswith("logo_ok") and row == (1, "svg"))
# 审查修复回归（10-10）：带生成器注释/DOCTYPE 的合法导出文件曾被误杀，现在必须放行
r = upload_logo(pid, tok, "c.svg",
                b'<!-- Generator: Adobe Illustrator 26.0.0 --><svg xmlns="http://www.w3.org/2000/svg"'
                b' viewBox="0 0 9 9"><rect width="9" height="9" fill="green"/></svg>')
check("带生成器注释的合法 SVG 不误杀", r.geturl().endswith("logo_ok"))
r = upload_logo(pid, tok, "d.svg",
                b'<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"'
                b' "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg'
                b' xmlns="http://www.w3.org/2000/svg" viewBox="0 0 9 9"><circle r="4"/></svg>')
check("带 DTD 声明的合法 SVG 不误杀", r.geturl().endswith("logo_ok"))
lp = os.path.join(ROOT, "data", "logos", f"{pid}.svg")
check("SVG 文件落盘", os.path.exists(lp))

resp = req(f"/subscribe/logo/{pid}")
body = resp.read()
check("读取路由 svg content-type+CSP+nosniff",
      resp.headers.get("Content-Type") == "image/svg+xml"
      and resp.headers.get("Content-Security-Policy") == "default-src 'none'"
      and resp.headers.get("X-Content-Type-Options") == "nosniff")
check("SVG 作为图片资源渲染（根=svg/xml 头）", b"<svg" in body)

r = upload_logo(pid, tok, "e.svg",
                b'<svg xmlns="x" onload="alert(1)"><script>alert(1)</script>'
                b'<a href="javascript:alert(2)"><text>x</text></a><rect/></svg>')
saved = open(lp, "rb").read()
check("恶意 SVG：script/on*/js-href 全被净化后才落库",
      r.geturl().endswith("logo_ok") and b"script" not in saved.lower()
      and b"onload" not in saved.lower() and b"javascript:" not in saved.lower())

r = upload_logo(pid, tok, "s.svg", b'<svg xmlns="x"><rect/></svg><script>tail()</script>')
saved = open(lp, "rb").read()
check("尾随 script 剥离后存净身", r.geturl().endswith("logo_ok") and b"script" not in saved.lower())
# 10-10 审查绕过样本：实体编码 js-href 现在整图拒绝（净化前探针看不见、解析树看得见）
r = upload_logo(pid, tok, "e2.svg",
                b'<svg xmlns="x"><a href="&#106;avascript:alert(1)">t</a><rect/></svg>')
check("实体编码 javascript: href 拒绝 bad_logo", r.geturl().endswith("bad_logo"))
r = upload_logo(pid, tok, "e3.svg",
                b'<svg xmlns="x" xmlns:p="urn:p"><p:script>alert(1)</p:script><rect/></svg>')
saved = open(lp, "rb").read()
check("命名空间前缀 <p:script> 被剥离（净身入库）",
      r.geturl().endswith("logo_ok") and b"script" not in saved.lower())

r = upload_logo(pid, tok, "b.svg", b'<svg' + bytes(range(0x80, 0xff, 2)))
check("非 UTF-8 伪 SVG 拒绝 bad_logo", r.geturl().endswith("bad_logo"))

r = upload_logo(pid, tok, "x.txt", b'<svg xmlns="x"><rect/></svg> not-really')
check("SVG 根判定=声明后必须 <svg 开头；尾随杂质过不了 XML 良构终审=拒绝（10-10 加严）",
      r.geturl().endswith("bad_logo"))
r = upload_logo(pid, tok, "g.gif", b"GIF89a" + b"\x00" * 40)
check("GIF 仍不在白名单=拒绝", r.geturl().endswith("bad_logo"))

png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
r = upload_logo(pid, tok, "p.png", png)
row = sqlite3.connect(DB).execute("SELECT logo_ext FROM subs WHERE id=?", (pid,)).fetchone()
check("PNG 旧通道不回归+换格式旧文件清理",
      r.geturl().endswith("logo_ok") and row[0] == "png"
      and not os.path.exists(lp))

conn = sqlite3.connect(DB)
conn.execute("DELETE FROM subs WHERE id=?", (pid,))
conn.execute("DELETE FROM alerts WHERE sub_id NOT IN (SELECT id FROM subs)")
conn.execute("DELETE FROM sub_pushes WHERE alert_id NOT IN (SELECT id FROM alerts)")
conn.commit()
conn.close()
for p in glob.glob(os.path.join(ROOT, "data", "logos", f"{pid}.*")):
    os.remove(p)
check("临时订阅与文件自清理",
      sqlite3.connect(DB).execute("SELECT COUNT(*) FROM subs WHERE id=?", (pid,)).fetchone()[0] == 0
      and not glob.glob(os.path.join(ROOT, "data", "logos", f"{pid}.*")))

fails = [n for n, ok in results if not ok]
print(f"\n{len(results)} 项，失败 {len(fails)}")
sys.exit(1 if fails else 0)
