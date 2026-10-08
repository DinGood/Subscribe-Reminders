"""推送 worker（订阅域）：pending -> sending -> delivered / retrying -> dead。
渠道=飞书卡片 + 邮件。"""
import asyncio
import json
import logging
import re
import time

import httpx

from . import config, db, subwatcher

log = logging.getLogger("sub.pusher")

_task: asyncio.Task | None = None
_running = False
_client: httpx.AsyncClient | None = None
_feishu_token: tuple[str, float] = ("", 0.0)
_RE_BOTURL = re.compile(r"bot\d+:[\w\-]+")


def _scrub(err: str) -> str:
    """错误串可能带完整请求 URL（内嵌 secret），入库/上页前替换掉。"""
    fc = config.feishu_cfg()
    for secret in (fc["app_secret"], fc["app_id"],
                   config.FEISHU_APP_SECRET, config.FEISHU_APP_ID):
        if secret and len(secret) >= 6:
            err = err.replace(secret, "***")
    try:  # SMTP 授权码/账号同样不得进错误串（纵深防御：smtplib 异常文本惯例不含密码，但不赌）
        from . import mailer
        sc = mailer.get_cfg()
        for secret in (sc.get("password", ""), sc.get("user", "")):
            if secret and len(secret) >= 6:
                err = err.replace(secret, "***")
    except Exception:
        pass
    err = _RE_BOTURL.sub("bot***", err)
    return err[:200]


async def feishu_send(payload_card: dict, chat_id: str,
                      client: httpx.AsyncClient | None = None) -> tuple[bool, int, str]:
    """经飞书开放平台 API 主动发消息。2xx 且 body code==0 才算成功。"""
    global _feishu_token
    c = client or _client
    assert c is not None
    fc = config.feishu_cfg()
    base = fc["api_base"]
    token, exp = _feishu_token
    if not token or exp <= time.time() + 60:
        r = await c.post(
            f"{base}/open-apis/auth/v3/tenant_access_token/internal",
            json={"app_id": fc["app_id"], "app_secret": fc["app_secret"]},
            timeout=config.PUSH_TIMEOUT_S)
        try:
            body = r.json()
        except Exception:
            body = {}
        if body.get("code") != 0 or not body.get("tenant_access_token"):
            return False, r.status_code, f"token失败: code={body.get('code')} {body.get('msg','')}"[:200]
        token = body["tenant_access_token"]
        _feishu_token = (token, time.time() + int(body.get("expire", 3600)))
    r = await c.post(
        f"{base}/open-apis/im/v1/messages",
        params={"receive_id_type": "chat_id"},
        headers={"Authorization": f"Bearer {token}"},
        json={"receive_id": chat_id, "msg_type": "interactive",
              "content": json.dumps(payload_card, ensure_ascii=False)},
        timeout=config.PUSH_TIMEOUT_S)
    try:
        body = r.json()
    except Exception:
        body = {}
    ok = 200 <= r.status_code < 300 and body.get("code") == 0
    err = "" if ok else f"code={body.get('code')} {body.get('msg','')} HTTP {r.status_code}"
    return ok, r.status_code, _scrub(err)


# ---------- 订阅提醒 payload ----------
_KIND_CN = {"yearly": "年付", "quarterly": "季付", "monthly": "月付",
            "weekly": "周付", "custom": "自定义周期", "once": "一次性"}


def money_of(a: dict) -> str:
    """金额+货币符号（快照字段拼装；无金额则空串）。用户已手打符号的金额不重复加。"""
    amt = (a.get("amount") or "").strip()
    if not amt:
        return ""
    if amt[0] in "¥$€£￥" or amt[:2] in ("C$", "US"):
        return amt
    sym = subwatcher.currencies().get(a.get("currency") or "CNY") or subwatcher._FALLBACK_CUR["sym"]
    return f"{sym}{amt}" if sym else amt


def alert_subject(a: dict) -> str:
    lead = a["lead_days"]
    tail = "今日到期" if lead <= 0 else f"还有 {lead} 天到期"
    lab = f"（{a['label']}）" if a.get("label") else ""
    return f"【订阅】{a['title']} {tail}{lab}"


def fmt_alert(a: dict) -> str:
    """五段式纯文本（邮件用）。"""
    kind = _KIND_CN.get(a.get("kind", "periodic"), "周期")
    lead = "今日到期" if a["lead_days"] <= 0 else f"提前 {a['lead_days']} 天"
    money = " / ".join(x for x in (money_of(a), (a.get("note") or "").strip()) if x) or "-"
    return ("【订阅续费提醒】\n"
            f"【订阅名称】{a['title']}\n"
            f"【类型】{kind}\n"
            f"【下次到期】{a['next_date']}（{lead}）\n"
            f"【金额备注】{money}\n"
            f"【提醒时间】{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(a['created_at']))}")


def alert_card(a: dict) -> dict:
    """飞书蓝头卡片。"""
    return {
        "header": {"title": {"tag": "plain_text", "content": alert_subject(a)},
                   "template": "blue"},
        "elements": [{"tag": "div", "text": {
            "tag": "lark_md", "content": fmt_alert(a).replace("【订阅续费提醒】\n", "")}}],
    }


def _fetch_sub_push_row(sp_id: int) -> dict | None:
    row = db.db().execute(
        "SELECT p.*, a.sub_id,a.title,a.lead_days,a.fire_date,a.next_date,a.amount,"
        "a.currency,a.note,a.kind,a.label,a.created_at, s.period, s.type as sub_type,"
        " w.name wh_name,w.url wh_url,w.fmt wh_fmt,w.enabled wh_enabled"
        " FROM sub_pushes p JOIN alerts a ON a.id=p.alert_id"
        " LEFT JOIN subs s ON s.id=a.sub_id"
        " JOIN webhooks w ON w.id=p.webhook_id WHERE p.id=?",
        (sp_id,)).fetchone()
    return dict(row) if row else None


async def _send_alert_once(row: dict) -> tuple[bool, int, str]:
    assert _client is not None
    fmt = row["wh_fmt"]
    if fmt == "feishu_bot":
        fc = config.feishu_cfg()
        if not (fc["app_id"] and fc["app_secret"]):
            return False, 0, "缺少飞书 App ID/Secret 配置"
        return await feishu_send(alert_card(row), fc["chat_id"])
    if fmt == "mail":
        from . import mailer
        return await mailer.send(alert_subject(row), fmt_alert(row))
    return False, 0, f"订阅渠道不支持的格式: {fmt}"


async def _tick_subs() -> None:
    conn = db.db()
    rows = conn.execute(
        "SELECT p.id FROM sub_pushes p JOIN webhooks w ON w.id=p.webhook_id"
        " WHERE p.status IN ('pending','retrying') AND p.next_attempt_at<=?"
        " AND w.enabled=1 ORDER BY p.id LIMIT 20",
        (db.now(),)).fetchall()
    for r in rows:
        row = _fetch_sub_push_row(r["id"])
        if row is None:
            # webhooks 行已删：永久 pending 无意义，标死信留痕
            conn.execute("UPDATE sub_pushes SET status='dead',last_error='渠道已删除',updated_at=? WHERE id=?",
                         (db.now(), r["id"]))
            conn.commit()
            continue
        if not row["wh_enabled"]:
            continue
        conn.execute("UPDATE sub_pushes SET status='sending',updated_at=? WHERE id=?",
                     (db.now(), r["id"]))
        conn.commit()
        try:
            ok, code, err = await _send_alert_once(row)
        except Exception as e:
            ok, code, err = False, 0, _scrub(f"{type(e).__name__}: {e}")
        now = db.now()
        attempts = row["attempts"] + 1
        if ok:
            conn.execute(
                "UPDATE sub_pushes SET status='delivered',attempts=?,response_code=?,"
                "last_error='',updated_at=? WHERE id=?", (attempts, code, now, r["id"]))
            log.info("订阅提醒推送成功: alert#%s -> %s", row["alert_id"], row["wh_name"])
        elif attempts >= config.PUSH_MAX_ATTEMPTS:
            conn.execute(
                "UPDATE sub_pushes SET status='dead',attempts=?,response_code=?,"
                "last_error=?,updated_at=? WHERE id=?", (attempts, code, err, now, r["id"]))
            log.warning("订阅提醒进死信: alert#%s -> %s err=%s", row["alert_id"], row["wh_name"], err)
        else:
            conn.execute(
                "UPDATE sub_pushes SET status='retrying',attempts=?,response_code=?,"
                "last_error=?,next_attempt_at=?,updated_at=? WHERE id=?",
                (attempts, code, err, now + _next_delay(attempts), now, r["id"]))
        conn.commit()


def requeue_dead_for_alert(alert_id: int) -> int:
    conn = db.db()
    cur = conn.execute(
        "UPDATE sub_pushes SET status='pending',attempts=0,next_attempt_at=0,"
        "last_error='',updated_at=? WHERE alert_id=? AND status='dead'",
        (db.now(), alert_id))
    conn.commit()
    return cur.rowcount


def sub_queue_counts() -> dict:
    conn = db.db()
    out = {}
    for r in conn.execute(
        "SELECT status,COUNT(DISTINCT alert_id) c FROM sub_pushes GROUP BY status"):
        out[r["status"]] = r["c"]
    return out


# 兼容 web 层调用名
queue_counts = sub_queue_counts


def _next_delay(attempts_done: int) -> int:
    if attempts_done <= len(config.PUSH_BACKOFF_S):
        return config.PUSH_BACKOFF_S[attempts_done - 1]
    return config.PUSH_BACKOFF_S[-1]


async def _loop() -> None:
    global _running, _client
    _client = httpx.AsyncClient()
    _running = True
    n = db.db().execute(
        "UPDATE sub_pushes SET status='pending',updated_at=? WHERE status='sending'",
        (db.now(),)).rowcount
    db.db().commit()
    if n:
        log.info("恢复中断的 sending 任务: %d", n)
    try:
        while _running:
            try:
                await _tick_subs()
            except Exception:
                log.exception("pusher tick 失败")
            await asyncio.sleep(config.PUSH_POLL_INTERVAL_S)
    finally:
        try:
            await _client.aclose()
        except Exception:
            pass  # 被 cancel 时清理不许多抛，保证 _task 可复位
        _client = None
        _running = False


def start() -> bool:
    global _task
    if _task is not None and not _task.done():
        return False
    _task = asyncio.create_task(_loop())
    return True


async def stop() -> None:
    global _running, _task
    _running = False
    if _task:
        try:
            await asyncio.wait_for(_task, timeout=30)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            _task.cancel()  # 宽限期没退干净就强杀，保证可重启（否则 _task 永占位）
        _task = None
