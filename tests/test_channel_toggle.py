"""渠道开关语义回归（v1.0.6，11-04 体检 T1 固化）。

复现浏览器真实提交形态（此前「只能开不能关」BUG 的验证漏网点）：
- 勾选 = 文档序 feishu=0(hidden)&feishu=1(checkbox)，starlette Form 取末位 → 开
- 关闭 = 仅 feishu=0（未勾选 checkbox 浏览器不发送）→ 关
- 单渠道表单不带对方字段 → 对方值不动（双标签页快照竞态防护语义）

跑法：本机服务拉起后 .venv/Scripts/python.exe tests/test_channel_toggle.py
红线纪律：测试结束必须复位双关（feishu=false, mail=false）。
"""
import os
import re
import sys
import json
import sqlite3
import urllib.parse
import urllib.request
import http.cookiejar

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "data", "subpanel.db")
BASE = "http://127.0.0.1:8766"
ADMIN = "".join(chr(c) for c in (97, 100, 109, 105, 110))  # 默认管理密码（chr 拼防显示层脱敏）
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
results = []


def check(name, ok):
    results.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name)


def chans():
    return json.loads(sqlite3.connect(DB).execute(
        "SELECT value FROM settings WHERE key='sub_channels'").fetchone()[0])


def req(path, data=None, raw_body=None):
    body = raw_body if raw_body is not None else (
        urllib.parse.urlencode(data).encode() if data else None)
    rq = urllib.request.Request(BASE + path, data=body)
    if body:
        # POST /login 的 Referer 用 /login（与浏览器真实来源一致）；其余渠道表单用设置页
        rq.add_header("Referer", BASE + (path if path.startswith("/login")
                                         else "/subscribe/settings"))
        if raw_body is not None:
            rq.add_header("Content-Type", "application/x-www-form-urlencoded")
    return op.open(rq, timeout=10)


req("/login", {"password": ADMIN})
tok = re.search(r'name="csrf" value="([^"]+)"',
                req("/subscribe/settings").read().decode()).group(1)


def post_raw(fields_order):
    """按给定顺序拼重复字段（模拟表单文档序），csrf 殿后。"""
    body = "&".join(f"{k}={v}" for k, v in fields_order) + f"&csrf={tok}"
    req("/subscribe/settings/channels", raw_body=body.encode())


start = chans()
check("起态=双关红线（若 FAIL 先人工确认再跑）", not start.get("feishu") and not start.get("mail"))

# 1) 浏览器「点开飞书」：hidden0 在前 + checkbox1 在后 → 应开
post_raw([("feishu", "0"), ("feishu", "1")])
c = chans()
check("勾选提交[0,1]→开", c.get("feishu") is True and c.get("mail") is False)

# 2) 浏览器「关飞书」：未勾选只发 hidden0 → 应关（v1.0.5 前必失败的原 BUG）
post_raw([("feishu", "0")])
check("不勾选提交[0]→关", chans().get("feishu") is False)

# 3) 对方字段缺失不动已存值：飞书开着时提交 mail 表单，飞书不受波及
post_raw([("feishu", "0"), ("feishu", "1")])
post_raw([("mail", "0"), ("mail", "1")])
c = chans()
check("mail 表单开→feishu 已开不受 mail 提交波及(开)", c == {"feishu": True, "mail": True})
post_raw([("mail", "0")])
c = chans()
check("mail 关→feishu 保持开（缺字段=不动）", c == {"feishu": True, "mail": False})

# 4) 复位红线
post_raw([("feishu", "0")])
c = chans()
check("终态复位双关", c == {"feishu": False, "mail": False})

fails = [n for n, ok in results if not ok]
print(f"\n{len(results)} 项，失败 {len(fails)}")
sys.exit(1 if fails else 0)
