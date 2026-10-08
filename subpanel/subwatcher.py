"""订阅提醒调度：每天 09:00 + 服务启动时各扫一轮。
周期项按 calendar 规则自动推算下次到期日（短月钳到月末，如 1/31 月付→2/28），
提前天数集合 {lead...,0} 命中即生成 alerts（uk 幂等，重启不重发）；
错过时点的补发窗口=当天 23:59 前，隔日作废记 skipped；
一次性项到期推完 0 天提醒后自动转 done（可改期复活）。
"""
import asyncio
import calendar
import json
import logging
import sqlite3
import threading
import time
from datetime import date, datetime

from . import config, db

log = logging.getLogger("sub.subwatcher")

_task: asyncio.Task | None = None
_inner: asyncio.Task | None = None  # 当前 _loop 任务（stop 时须一并取消，防 orphan 双跑）
_running = False
_beat: float = 0.0  # 心跳时间戳（_loop 每段更新，_supervise 判卡死用）

# 全局提醒频率（模块级设置；提前 1-7 天单选 + 到期当天默认必提）
_FREQ_KEY = "sub_alert_freq"
DEFAULT_FREQ = {"days": 7, "hour": 9}


def freq() -> dict:
    out = dict(DEFAULT_FREQ)
    d: dict = {}
    raw = db.get_setting(_FREQ_KEY)
    if raw:
        try:
            d = json.loads(raw)
            if isinstance(d, dict):
                out.update(d)
        except Exception:
            pass
    # 兼容旧格式 leads 串（如 "7,3,1,0"）→ 取最大天数（仅当存库的原 dict 无 days 键）
    if "days" not in d:
        nums = [int(x) for x in str(out.pop("leads", "")).split(",") if x.strip().isdigit()]
        out["days"] = max(nums) if nums else 7
        if out["days"] < 1:
            out["days"] = 1  # 旧"仅当天"档 → 就近折算为提前 1 天（含当天仍必提）
    else:
        out.pop("leads", None)
    try:
        out["days"] = int(out["days"])
        if not 1 <= out["days"] <= 7:
            out["days"] = 7
    except Exception:
        out["days"] = 7
    try:
        h = int(out["hour"])
        out["hour"] = h if 0 <= h <= 23 else 9
    except Exception:
        out["hour"] = 9
    return out


def set_freq(d: dict) -> None:
    cur = freq()
    days = d.get("days", cur["days"])
    hour = d.get("hour", cur["hour"])
    db.set_setting(_FREQ_KEY, json.dumps({"days": int(days), "hour": int(hour)}))


def local_today(dts: float | None = None) -> date:
    return datetime.fromtimestamp(dts if dts is not None else time.time()).date()


def _add_months(d: date, n: int) -> date:
    y, m = divmod(d.month - 1 + n, 12)
    y += d.year
    m += 1
    return date(y, m, min(d.day, calendar.monthrange(y, m)[1]))  # 短月钳到月末


def advance(next_d: date, period: str, custom_days: int) -> date:
    if period == "weekly":
        return next_d + config.timedelta(days=7)
    if period == "custom":
        return next_d + config.timedelta(days=max(custom_days or 1, 1))
    step = {"yearly": 12, "quarterly": 3, "monthly": 1}.get(period)
    if step:
        return _add_months(next_d, step)
    raise ValueError(f"未知周期: {period}")


def _parse(s: str) -> date:
    return datetime.strptime(s.strip(), "%Y-%m-%d").date()


def _fired_keys(s: dict) -> set[str]:
    """fired 串 → 精确集合（防子串误判：键格式若演变，`in 串` 会把前缀当已发）。"""
    return {k for k in (s.get("fired") or "").split(",") if k}


def scan(now_ts: int | None = None) -> int:
    """一轮扫描。返回新生成的提醒条数（不含 skipped）。可测，无事件循环依赖。
    提前天数与触发钟点=模块全局设置 freq()（2026-10-03 起，不再按单条订阅配置）。
    逐行隔离：单行异常（脏周期/极端日期）只跳过该行，不饿死后续订阅。"""
    now = now_ts if now_ts is not None else int(time.time())
    today = datetime.fromtimestamp(now).date()
    fq = freq()
    g_leads = sorted(range(fq["days"] + 1), reverse=True)  # 每日连催：提前 N 天起每天一次直到到期当天（含当天）
    fire_min = fq["hour"] * 60
    now_min = datetime.fromtimestamp(now).hour * 60 + datetime.fromtimestamp(now).minute
    conn = db.db()
    new = 0
    for row in conn.execute("SELECT * FROM subs").fetchall():
        try:
            new += _scan_row(dict(row), now, today, g_leads, fire_min, now_min, conn)
        except Exception:
            conn.rollback()
            log.exception("订阅项扫描失败（跳过该行）: id=%s", row["id"])
    return new


def _scan_row(s: dict, now: int, today: date, g_leads: list[int],
              fire_min: int, now_min: int, conn) -> int:
    new = 0
    try:
        next_d = _parse(s["next_date"])
    except ValueError:
        return 0
    if s["type"] == "once":
        if s["status"] == "done":
            return 0
        if s["enabled"] and next_d == today and now_min >= fire_min:
            leads = [0]
        elif next_d < today:
            if s.get("last_reminded_at"):
                conn.execute("UPDATE subs SET status='done' WHERE id=?", (s["id"],))
            elif s["enabled"]:
                # 逾期未响（当时没开机错过且过了补发窗）：标逾期不追发
                conn.execute("UPDATE subs SET status='overdue' WHERE id=?", (s["id"],))
            else:
                return 0  # 停用项不定态
            conn.commit()
            return 0
        else:
            return 0
    else:
        if not s["enabled"]:
            return 0
        leads = g_leads if now_min >= fire_min else []  # 未到全局钟点先不动作（跳过 fired 修剪保持原值）
        raw_fired = [k for k in (s.get("fired") or "").split(",") if k]
        s["fired"] = ",".join(raw_fired[-60:])  # 防幂等键串无限膨胀（保留近 60 条足够）
    # 提前天数命中集合（含 0=到期当天）；自动推算推进下次日期
    for lead in sorted(set(leads), reverse=True):
        fire_date = next_d - config.timedelta(days=lead)
        fired_key = f"{today.isoformat()}:{lead}"
        if fire_date == today:
            if fired_key in _fired_keys(s):
                continue
            new += _fire(s, lead, today, now, conn)
            s["fired"] = (s["fired"] + "," if s.get("fired") else "") + fired_key
            conn.execute("UPDATE subs SET fired=?,last_reminded_at=? WHERE id=?",
                         (s["fired"], now, s["id"]))
        elif fire_date < today:
            # 隔日错过=作废记 skipped（当天错过由 fire_date==today 分支自然补发）；
            # 早于订阅创建日的历史欠账静默跳过，不记 skipped
            missed_key = f"{fire_date.isoformat()}:{lead}"
            if missed_key in _fired_keys(s):
                continue
            created_day = datetime.fromtimestamp(s.get("created_at") or 0).date()
            if fire_date >= created_day:
                _skip(s, lead, fire_date, conn)
            s["fired"] = (s["fired"] + "," if s.get("fired") else "") + missed_key
            conn.execute("UPDATE subs SET fired=? WHERE id=?", (s["fired"], s["id"]))
    conn.commit()
    # 周期自动推进：到期日已过则滚到下一期（提醒状态跟随新周期）
    if s["type"] == "periodic":
        nd = next_d
        guard = 0
        while nd <= today and guard < 1000:
            nd = advance(nd, s["period"], s["custom_days"] or 0)
            guard += 1
        if nd != next_d:
            conn.execute("UPDATE subs SET next_date=?,status='active' WHERE id=?",
                         (nd.isoformat(), s["id"]))
            conn.commit()
        if nd <= today:  # guard 用尽=数据异常（间隔 0），停止推进防死循环
            log.warning("订阅项 #%s 周期推算异常，停止自动推进", s["id"])
    return new


def _fire(s: dict, lead: int, fire_day: date, now: int, conn, backfill: bool = False) -> int:
    """生成一条 alerts + 按启用渠道入推队列。返回 1。"""
    label = "补发" if backfill else ""
    kind = "once" if s["type"] == "once" else s.get("period", "monthly")
    try:
        cur = conn.execute(
            "INSERT INTO alerts(sub_id,title,lead_days,fire_date,next_date,amount,currency,"
            "note,kind,label,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (s["id"], s["title"], lead, fire_day.isoformat(), s["next_date"],
             s.get("amount") or "", s.get("currency") or "CNY",
             s.get("note") or "", kind, label, now))
    except sqlite3.IntegrityError:
        # uk(sub_id,fire_date,lead) 冲突=该档已生成过。改期复活（web 清 fired）后会走到这里：
        # 把旧 alert 的 delivered/dead 推送复位重发，否则 fired 显示未发但永远不再送达（静默缺发）。
        old = conn.execute("SELECT id FROM alerts WHERE sub_id=? AND fire_date=? AND lead_days=?",
                           (s["id"], fire_day.isoformat(), lead)).fetchone()
        if old:
            conn.execute("UPDATE sub_pushes SET status='pending',attempts=0,next_attempt_at=0,"
                         "last_error='',updated_at=? WHERE alert_id=? AND status IN ('delivered','dead')",
                         (now, old["id"]))
            conn.commit()
        return 0
    except Exception:
        conn.rollback()
        log.exception("订阅提醒写入失败（非幂等冲突）: sub=%s lead=%s", s["id"], lead)
        return 0
    alert_id = cur.lastrowid
    chans = channels()
    ids = {}  # 优先订阅专属行（name 前缀）
    for fmt in ("feishu_bot", "mail"):
        w = conn.execute("SELECT id FROM webhooks WHERE fmt=? AND name LIKE '订阅%'"
                         " ORDER BY id LIMIT 1", (fmt,)).fetchone()
        if w is None:
            w = conn.execute("SELECT id FROM webhooks WHERE fmt=? ORDER BY id LIMIT 1",
                             (fmt,)).fetchone()
        if w:
            ids[fmt] = w["id"]
    for key, fmt in (("feishu", "feishu_bot"), ("mail", "mail")):
        if chans.get(key) and fmt in ids:
            conn.execute(
                "INSERT OR IGNORE INTO sub_pushes(alert_id,webhook_id,status,attempts,"
                "next_attempt_at,last_error,response_code,updated_at)"
                " VALUES(?,?,'pending',0,0,'',NULL,?)",
                (alert_id, ids[fmt], now))
    conn.commit()
    log.info("订阅提醒生成: %s lead=%s 天 %s", s["title"], lead, label)
    return 1


def _skip(s: dict, lead: int, fire_day: date, conn) -> None:
    kind = "once" if s["type"] == "once" else s.get("period", "monthly")
    conn.execute(
        "INSERT OR IGNORE INTO alerts(sub_id,title,lead_days,fire_date,next_date,amount,"
        "currency,note,kind,label,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (s["id"], s["title"], lead, fire_day.isoformat(), s["next_date"],
         s.get("amount") or "", s.get("currency") or "CNY",
         s.get("note") or "", kind, "skipped", db.now()))
    conn.commit()


# 专属渠道行（固定 id，首启自动建）
CH_FEISHU, CH_MAIL = 101, 103
DEFAULT_CHANNELS = {"feishu": False, "mail": False}  # 默认双关，用户在设置页自行开启（首启不盲推）

# 金额货币（存代码，展示/推送快照加符号）
CURRENCIES = {"CNY": "¥", "USD": "US$", "CAD": "C$"}  # 默认映射（settings 无 sub_curs 时用）
_SUB_CURS_KEY = "sub_curs"  # 币种管理（设置页增删）


_FALLBACK_CUR = {"code": "CNY", "name": "人民币", "sym": "¥"}
_CUR_DEFAULT = [("CNY", "人民币", "¥"), ("USD", "美元", "US$"), ("CAD", "加拿大元", "C$")]


def cur_table() -> list[dict]:
    """货币表 [{code,name,sym}]（设置页可自由增删，无锁定项）。空=回退默认三币种；
    至少保留 1 项由删除路由保证；引用到不在表内的代码=回退 _FALLBACK_CUR 显示。"""
    import json as _json
    raw = db.get_setting(_SUB_CURS_KEY, "")
    rows = []
    try:
        for x in _json.loads(raw):
            code = str(x.get("code", "")).strip().upper()
            sym = str(x.get("sym", "")).strip()
            name = str(x.get("name", "")).strip()[:12]
            if code and sym:
                rows.append({"code": code, "name": name or code, "sym": sym})
    except Exception:
        rows = []
    if not rows:
        rows = [{"code": c, "name": n, "sym": s} for c, n, s in _CUR_DEFAULT]
    return rows


def currencies() -> dict:
    return {r["code"]: r["sym"] for r in cur_table()}


def channels() -> dict:
    raw = db.get_setting("sub_channels")
    out = dict(DEFAULT_CHANNELS)
    if raw:
        try:
            import json
            out.update(json.loads(raw))
        except Exception:
            pass
    return out


def set_channels(d: dict) -> None:
    import json
    db.set_setting("sub_channels", json.dumps({**channels(), **d}))


def ensure_default_subs() -> None:
    """首启建订阅专属的渠道 webhooks 行（固定 id）。"""
    conn = db.db()
    now = db.now()
    for wh_id, name, url, fmt in ((CH_FEISHU, "订阅飞书", "feishu://api", "feishu_bot"),
                                  (CH_MAIL, "订阅邮件", "smtp://api", "mail")):
        conn.execute("INSERT OR IGNORE INTO webhooks(id,name,url,fmt,enabled,created_at)"
                     " VALUES(?,?,?,?,1,?)", (wh_id, name, url, fmt, now))
    conn.commit()
    if not db.get_setting("sub_channels"):
        set_channels(DEFAULT_CHANNELS)


_rescan_lock = threading.Lock()


def rescan() -> int:
    """串行化入口：路由与调度线程共用，防两线程并发读-改-写 subs.fired 丢更新。"""
    with _rescan_lock:
        try:
            ensure_default_subs()
            return scan()
        except Exception:
            log.exception("订阅扫描失败")
            return 0


def _today_fire_ts(now: float) -> float:
    """今天的全局钟点时间戳（频率改了也按新值）。"""
    lt = time.localtime(now)
    fq = freq()
    return datetime(lt.tm_year, lt.tm_mon, lt.tm_mday).replace(
        hour=int(fq["hour"]), minute=config.SUB_FIRE_MIN).timestamp()


async def _loop() -> None:
    """调度主循环。只在 _running=False 时正常退出；任何异常/卡死交给
    _supervise() 看门狗记录并重启（2026-10-06 加护，此前循环自灭=无声错过钟点）。"""
    global _running, _beat
    _running = True
    # 启动即补扫一轮（错过的当天提醒在补发窗口内）
    await asyncio.to_thread(rescan)
    last_scan = time.time()
    _beat = last_scan
    while _running:
        now = time.time()
        _beat = now
        tf = _today_fire_ts(now)
        # 休眠/卡顿跨过钟点的补扫：醒来看见"今天钟点已过但调度从未扫过"就补
        if now >= tf and last_scan < tf:
            n = await asyncio.to_thread(rescan)
            last_scan = time.time()
            _beat = last_scan
            log.info("调度补扫（钟点已过/唤醒）: 新增提醒 %d", n)
            continue
        nxt = _next_fire_ts(now)
        wait = min(max(nxt - now, 1), 600)  # 分段睡眠，停止/重启 10 分钟内生效
        await asyncio.sleep(wait)
        if not _running:
            return
        if time.time() >= nxt - 1:
            n = await asyncio.to_thread(rescan)
            last_scan = time.time()
            _beat = last_scan
            log.info("调度定点扫描: 新增提醒 %d", n)


_WATCHDOG_TICK_S = 60
_STALL_LIMIT_S = 1800
_RESTART_BACKOFF_S = (5, 30, 120, 300)


async def _supervise() -> None:
    """外层看护 _loop：崩溃→落 traceback+退避重启；心跳超时→判卡死强制重启。
    stop()（置 _running=False 并取消本任务）是唯一退出通道。"""
    global _beat, _inner
    attempt = 0
    while _running:
        _beat = time.time()
        inner = asyncio.create_task(_loop())
        _inner = inner
        reason = None
        while True:
            done, _ = await asyncio.wait({inner}, timeout=_WATCHDOG_TICK_S)
            if done:
                break
            if time.time() - _beat > _STALL_LIMIT_S:
                log.error("订阅调度心跳丢失超 %s 秒，判卡死强制重启", _STALL_LIMIT_S)
                reason = "stall"
                break
        if reason is None:
            try:
                inner.result()
            except asyncio.CancelledError:
                if not inner.done():
                    inner.cancel()
                return
            except Exception:
                log.exception("订阅调度循环崩溃，退避后自动重启")
                reason = "crash"
        else:
            if not inner.done():
                inner.cancel()
        if not _running:
            return
        delay = _RESTART_BACKOFF_S[min(attempt, len(_RESTART_BACKOFF_S) - 1)]
        attempt += 1
        log.warning("订阅调度重启（第 %d 次，原因=%s，延迟 %s 秒）", attempt, reason, delay)
        await asyncio.sleep(delay)


def start() -> bool:
    global _task, _running, _beat
    if _task is not None and not _task.done():
        return False
    _running = True
    _beat = time.time()
    _task = asyncio.create_task(_supervise())
    return True


async def stop() -> None:
    global _running, _task, _inner
    _running = False
    if _inner and not _inner.done():
        _inner.cancel()  # 内层 _loop 必须一起取消：否则 orphan 醒后 while _running 若被
        # 新一轮 start 置回 True 会继续跑=双调度并发（10-08 审查 L5）
    if _task:
        _task.cancel()
        try:
            await _task
        except (asyncio.CancelledError, Exception):
            pass
        _task = None
    _inner = None


def _next_fire_ts(now: float) -> float:
    lt = time.localtime(now)
    hour = freq()["hour"]
    fire_min = hour * 60 + config.SUB_FIRE_MIN
    fired_today = (lt.tm_hour * 60 + lt.tm_min) >= fire_min
    target = datetime(lt.tm_year, lt.tm_mon, lt.tm_mday).replace(
        hour=hour, minute=config.SUB_FIRE_MIN)
    if fired_today:
        target = target + config.timedelta(days=1)
    return target.timestamp()
