"""调度器/安全哈希离线断言（不碰生产 data/，独立临时库）。
跑法：.venv/Scripts/python.exe tests/test_scheduler_offline.py（无需服务在跑）
覆盖：毒行逐条隔离、uk 冲突复活复位、scrypt 前缀、旧 HMAC 哈希无感升级、错密拒绝。
"""
import os
import sys
import tempfile
import time
import hmac

os.environ["SUB_DATA_DIR"] = tempfile.mkdtemp()  # 必须先于 import config
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from subpanel import db  # noqa: E402
db.init_db()
from subpanel import subwatcher as sw  # noqa: E402
from subpanel import web  # noqa: E402

conn = db.db()
now = int(time.time())

# --- 1. 毒行隔离：bogus 周期行异常被逐行捕获，正常行照常产出 ---
for sid, period in ((901, "bogus"), (902, "monthly")):
    conn.execute(
        "INSERT INTO subs(id,title,category,type,period,custom_days,next_date,leads,"
        "amount,currency,note,enabled,status,fired,created_at)"
        " VALUES(?,'T','x','periodic',?,0,date('now'),'',0,'CNY','',1,'active','',?)",
        (sid, period, now))
conn.commit()
sw.set_freq({"days": 3, "hour": 0})
n = sw.rescan()
assert n >= 1, "毒行饿死了正常行"
print("PASS 毒行逐条隔离 (new =", n, ")")

# --- 2. _fire uk 冲突→delivered 复位 pending（改期复活不再静默缺发） ---
sw.ensure_default_subs()
from subpanel import config  # noqa: E402
import json  # noqa: E402
db.set_setting("sub_channels", json.dumps({"feishu": False, "mail": False}))
conn.execute(
    "INSERT INTO subs(id,title,category,type,period,custom_days,next_date,leads,"
    "amount,currency,note,enabled,status,fired,created_at)"
    " VALUES(903,'R','x','periodic','monthly',0,date('now'),'',0,'CNY','',1,'active','',?)",
    (now,))
conn.commit()
today = sw.local_today(now)
s = dict(conn.execute("SELECT * FROM subs WHERE id=903").fetchone())
r1 = sw._fire(s, 0, today, now, conn)
r2 = sw._fire(s, 0, today, now, conn)
assert (r1, r2) == (1, 0), f"首发应为1、uk 冲突应为0：{r1},{r2}"
aid = conn.execute("SELECT id FROM alerts WHERE sub_id=903").fetchone()[0]
conn.execute("INSERT INTO sub_pushes(alert_id,webhook_id,status,attempts,next_attempt_at,"
             "last_error,updated_at) VALUES(?,101,'delivered',1,0,'',?)", (aid, now))
conn.commit()
sw._fire(s, 0, today, now, conn)
st = conn.execute("SELECT status FROM sub_pushes WHERE alert_id=?", (aid,)).fetchone()[0]
assert st == "pending", f"uk 复活未复位推送: {st}"
print("PASS uk 冲突复活复位 delivered->pending")

# --- 3. scrypt 哈希 + 旧 h: HMAC 无感升级 + 错密拒绝 ---
web._hash_pw("warmup")  # 生成 pw_salt
salt = db.get_setting("pw_salt")
assert salt
assert web._hash_pw("any").startswith("s:")
db.set_setting("admin_pw_hash", "h:" + hmac.new(salt.encode(), b"legacy-pw", "sha256").hexdigest())
assert web._check_pw("legacy-pw") is True, "旧哈希兼容路径失效"
assert db.get_setting("admin_pw_hash").startswith("s:"), "旧哈希未升级 scrypt"
assert web._check_pw("wrong-pw") is False, "错密竟然通过"
print("PASS scrypt/旧哈希升级/错密拒绝")

# --- 4. fired 键精确匹配（子串误判回归） ---
s2 = dict(conn.execute("SELECT * FROM subs WHERE id=903").fetchone())
s2["fired"] = "2026-01-01:1"  # 前缀与 :11 形态相似
assert "2026-01-01:11" not in sw._fired_keys(s2), "子串误判回潮"
assert "2026-01-01:1" in sw._fired_keys(s2)
print("PASS fired 键精确集合匹配")

print()
print("RESULT: ALL OFFLINE ASSERTS PASS")
