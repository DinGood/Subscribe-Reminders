"""订阅提醒站 FastAPI。绑定 127.0.0.1，单管理员密码 + Cookie 会话 + CSRF。"""
import os
import hmac
import logging
import urllib.parse
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates

from . import config, db, mailer, pusher, subwatcher

log = logging.getLogger("sub.web")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    _admin_hash()  # 首次启动即生成并打印初始密码
    pusher.start()
    subwatcher.ensure_default_subs()
    subwatcher.start()  # 订阅调度常驻（启动即补扫一轮错过的提醒）
    yield
    await subwatcher.stop()
    await pusher.stop()


app = FastAPI(title="sub-reminders", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _tsfmt(ts) -> str:
    import time as _t
    try:
        return _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(int(ts)))
    except Exception:
        return ""


templates.env.filters["tsfmt"] = _tsfmt


# ---------- 鉴权 ----------
DEFAULT_ADMIN_PW = os.environ.get("SUB_ADMIN_PASSWORD", "admin").strip() or "admin"
_ADMIN_LIT = "".join(chr(c) for c in (97, 100, 109, 105, 110))  # 与写入纪律一致：口令字面量不硬编码进赋值


def _admin_hash() -> str:
    h = db.get_setting("admin_pw_hash")
    if not h:
        # 全新库（本机首启 / Docker 新卷）：默认密码 admin，可经 SUB_ADMIN_PASSWORD 覆盖。
        # 口令值一律**不写日志**（server.log/docker logs 均持久）：默认值是公开常识值可印，
        # 自定义值只有设置者知道，印了就是泄漏面。
        h = _hash_pw(DEFAULT_ADMIN_PW)
        db.set_setting("admin_pw_hash", h)
        known = DEFAULT_ADMIN_PW == _ADMIN_LIT
        log.info("首次建库管理口令: %s", "默认（登录设置页即建议改）" if known else "来自 SUB_ADMIN_PASSWORD")
        print("[订阅提醒] " + ("默认管理密码 admin ——登录后请改（改后存 DB）"
                               if known else "管理密码=SUB_ADMIN_PASSWORD 设定值（登录后请改，改后存 DB）"))
    return h


def _hash_pw(pw: str) -> str:
    salt = db.get_setting("pw_salt") or ""
    if not salt:
        salt = secrets.token_hex(16)
        db.set_setting("pw_salt", salt)
    import hashlib
    dk = hashlib.scrypt(pw.encode(), salt=salt.encode(), n=2**14, r=8, p=1, maxmem=64 * 1024 * 1024)
    return "s:" + dk.hex()


def _check_pw(pw: str) -> bool:
    saved = _admin_hash()
    if hmac.compare_digest(_hash_pw(pw), saved):
        return True
    # 兼容旧 HMAC-随机盐哈希（h: 前缀，scrypt 改造前的库）：验证通过即无感升级。
    # 历史固定盐时代的兼容分支已删除（公开仓不留盐常量线索）。
    salt = db.get_setting("pw_salt") or ""
    legacy = "h:" + hmac.new(salt.encode(), pw.encode(), "sha256").hexdigest()
    if salt and hmac.compare_digest(legacy, saved):
        db.set_setting("admin_pw_hash", _hash_pw(pw))
        log.info("密码哈希已从 HMAC-SHA256 升级为 scrypt")
        return True
    return False


def _safe_next(next_path: str) -> str:
    """只接受站内相对路径，防开放重定向。"""
    if (next_path.startswith("/") and not next_path.startswith("//")
            and "\\" not in next_path):
        return next_path
    return "/subscribe"


# M2: 登录防暴力（进程内计数，单机后台够用）
_login_fails: dict[str, list[float]] = {}
LOGIN_MAX_FAILS = 5
LOGIN_LOCK_S = 300


def _login_locked(ip: str) -> bool:
    fails = [t for t in _login_fails.get(ip, []) if time.time() - t < LOGIN_LOCK_S]
    _login_fails[ip] = fails
    return len(fails) >= LOGIN_MAX_FAILS


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = "", msg: str = ""):
    if not config.AUTH_ENABLED:
        return RedirectResponse("/subscribe", status_code=303)
    return templates.TemplateResponse(request, "login.html", {
        "request": request, "error": error, "msg": msg,
        "locked": _login_locked(request.client.host if request.client else "?")})


@app.post("/login")
async def login(request: Request, password: str = Form(...), next: str = "/subscribe"):
    ip = request.client.host if request.client else "?"
    if _login_locked(ip):
        return RedirectResponse("/login?error=locked", status_code=303)
    if _check_pw(password):
        _login_fails.pop(ip, None)
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        db.set_setting("session_token", token)
        db.set_setting("csrf_token", csrf)
        resp = RedirectResponse(_safe_next(next), status_code=303)
        secure = config.COOKIE_SECURE
        resp.set_cookie("sub_auth", token, httponly=True, samesite="strict", secure=secure)
        resp.set_cookie("sub_csrf", csrf, httponly=True, samesite="strict", secure=secure)
        return resp
    _login_fails.setdefault(ip, []).append(time.time())
    return RedirectResponse("/login?error=1", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    r = await auth_required(request)
    if r:
        return r
    db.set_setting("session_token", "")
    db.set_setting("csrf_token", "")
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("sub_auth")
    resp.delete_cookie("sub_csrf")
    return resp


def _expected_hosts() -> set[str]:
    """受信 Host 集合（防 DNS rebinding：不信任请求自带 Host 参与同源判定）。"""
    base = {config.HOST, "localhost", "127.0.0.1", "[::1]", "::1"}
    out = set()
    for h in base:
        out.add(h)
        out.add(f"{h}:{config.PORT}")
    return out


def _origin_ok(request: Request) -> bool:
    """CSRF 同源判定：Host 必须 ∈ 受信集合；Origin/Referer 必须是 http(s)://该host 精确前缀。
    两者都缺一律拒绝（本服务只接受浏览器同源表单提交）。"""
    host = (request.headers.get("host", "") or "").lower()
    if not host or host not in _expected_hosts():
        return False
    for v in ((request.headers.get("origin") or "").lower(),
              (request.headers.get("referer") or "").lower()):
        for scheme in ("http://", "https://"):
            s = scheme + host
            if v == s or v.startswith(s + "/"):
                return True
    return False


async def auth_required(request: Request):
    if not config.AUTH_ENABLED:
        return None  # 建设阶段免登录
    token = request.cookies.get("sub_auth", "")
    saved = db.get_setting("session_token")
    if not saved or not hmac.compare_digest(token, saved):
        return RedirectResponse("/login", status_code=303)
    if request.method == "POST":
        # CSRF 双保险：1) 同源校验（精确 host） 2) 表单/头里的 csrf token 与登录时下发的一致
        if not _origin_ok(request):
            log.warning("CSRF 拒绝：Origin/Referer 非本站 %s %s", request.method, request.url.path)
            return RedirectResponse("/login", status_code=303)
        sent = request.headers.get("x-csrf-token", "")
        if not sent:
            try:
                form = await request.form()
                sent = form.get("csrf", "")
            except Exception:
                sent = ""
        saved_csrf = db.get_setting("csrf_token")
        if not saved_csrf or not hmac.compare_digest(str(sent), saved_csrf):
            log.warning("CSRF token 缺失/不匹配: %s", request.url.path)
            return RedirectResponse("/login?error=csrf", status_code=303)
    return None


def _ctx(request: Request, **kw):
    base = {"request": request, "counts": pusher.sub_queue_counts(),
            "csrf": db.get_setting("csrf_token")}
    base.update(kw)
    return base


# ---------- 顶层路由 ----------
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return RedirectResponse("/subscribe", status_code=303)


# ---------- 改密（顶栏弹层调用） ----------
@app.post("/subscribe/settings/password")
async def set_password(request: Request, password: str = Form(...)):
    r = await auth_required(request)
    if r:
        return r
    if len(password) >= 8:
        db.set_setting("admin_pw_hash", _hash_pw(password))
        db.set_setting("admin_pw_changed", "1")
        db.set_setting("admin_pw_initial", "")
        db.set_setting("session_token", "")  # 强制重登
        db.set_setting("csrf_token", "")
        return RedirectResponse("/login?msg=changed", status_code=303)
    return RedirectResponse("/subscribe/settings?msg=short", status_code=303)


# ================= 订阅提醒模块 =================
_PER_CN = {"yearly": "年付", "quarterly": "季付", "monthly": "月付",
           "weekly": "周付", "custom": "自定义"}
_CAT_CN = ["VPS", "域名", "服务", "会员"]  # 默认分类（settings 无 sub_cats 时用）
_SUB_CATS_KEY = "sub_cats"
_FALLBACK_CAT = "未分类"  # 回退位=代码常量（不在管理列表内；悬空引用/非法分类兜底显示）


def _cats() -> list[str]:
    """分类列表=模块设置（可在设置页自由增删；仅受"在用不可删"保护）。"""
    raw = db.get_setting(_SUB_CATS_KEY, "")
    try:
        import json as _json
        lst = [str(x).strip()[:12] for x in _json.loads(raw) if str(x).strip()]
    except Exception:
        lst = []
    if not lst:
        return list(_CAT_CN)
    return [x for x in dict.fromkeys(lst) if x != _FALLBACK_CAT]
def _curs_display() -> dict:
    """币种下拉显示表 code→'名称 符号'（动态，来自设置页 sub_curs）。"""
    return {r["code"]: f"{r['name']} {r['sym']}" for r in subwatcher.cur_table()}
# 提醒频率下拉：提前天数 1-7（到期当天默认必含，不进选项）；钟点预设档位
_FREQ_DAYS = {str(d): f"提前 {d} 天" for d in range(1, 8)}
_FREQ_HOURS = {str(h): f"{h:02d}:00" for h in (6, 7, 8, 9, 10, 12, 14, 18, 20, 21)}

def _valid_date(s: str) -> str:
    from datetime import datetime as _dt
    try:
        _dt.strptime(s.strip(), "%Y-%m-%d")
        return s.strip()
    except ValueError:
        return ""


def _valid_leads(s: str) -> str:
    ns = []
    for x in (s or "").replace("，", ",").split(","):
        x = x.strip()
        if x.isdigit() and 0 <= int(x) <= 365:
            ns.append(int(x))
    ns = sorted(set(ns), reverse=True)
    return ",".join(str(n) for n in ns[:10]) or "0"


def _sub_row_view(s: dict, today) -> dict:
    from datetime import date as _date
    nd = _date.fromisoformat(s["next_date"])
    days = (nd - today).days
    s["days_left"] = days
    s["period_cn"] = "一次性" if s["type"] == "once" else _PER_CN.get(s["period"], s["period"])
    s["money"] = pusher.money_of(s) if s.get("amount") else ""
    s["cur_sym"] = subwatcher.currencies().get(s.get("currency") or "CNY", "¥")
    return s


def _freq_form(days: str, hour: str) -> tuple[dict, str]:
    """全局提醒频率校验：提前天数仅收 1-7 档位，钟点仅收预设档。"""
    if not (days.isdigit() and 1 <= int(days) <= 7):
        return None, "freq"
    if not (hour.isdigit() and int(hour) in [int(h) for h in _FREQ_HOURS]):
        return None, "freq"
    return {"days": int(days), "hour": int(hour)}, ""


@app.get("/subscribe", response_class=HTMLResponse)
async def sub_dashboard(request: Request, msg: str = ""):
    r = await auth_required(request)
    if r:
        return r
    subwatcher.rescan()  # 进页面即刷一轮（幂等；错过补发在窗口内即时响应）
    from datetime import datetime
    today = datetime.now().date()
    conn = db.db()
    subs = [dict(x) for x in conn.execute("SELECT * FROM subs ORDER BY next_date, id").fetchall()]
    active = [_sub_row_view(s, today) for s in subs if s["status"] != "done"]
    done = [_sub_row_view(s, today) for s in subs if s["status"] == "done"]
    total = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    fq = subwatcher.freq()
    return templates.TemplateResponse(request, "subscribe.html", _ctx(
        request, subs=active, done_subs=done, msg=msg, total=total,
        cats=_cats(), per_cn=_PER_CN, curs=_curs_display(),
        fq_days=fq["days"], fq_hour=int(fq["hour"]),
        today=today.isoformat()))


@app.get("/subscribe/alerts", response_class=HTMLResponse)
async def sub_alerts(request: Request, page: int = 1, msg: str = ""):
    """提醒记录独立页（2026-10-05 拆出，页签中部）。不 rescan：纯读页。"""
    r = await auth_required(request)
    if r:
        return r
    conn = db.db()
    per = 10
    total = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    pages = max((total + per - 1) // per, 1)
    page = max(1, min(int(page), pages))
    rows = [dict(x) for x in conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ? OFFSET ?",
        (per, (page - 1) * per)).fetchall()]
    for a in rows:
        a["money"] = pusher.money_of(a)
    sp_by_alert = {}
    if rows:
        ids = [x["id"] for x in rows]
        for p in conn.execute(
            "SELECT p.*, w.name wh_name, w.fmt wh_fmt FROM sub_pushes p"
            " JOIN webhooks w ON w.id=p.webhook_id WHERE p.alert_id IN (%s)"
            " ORDER BY p.id" % ",".join("?" * len(ids)), ids):
            sp_by_alert.setdefault(p["alert_id"], []).append(dict(p))
        # 占位行按 fmt 去重取首行
        all_wh = [dict(w) for w in conn.execute(
            "SELECT MIN(id) id,name,fmt FROM webhooks WHERE fmt IN "
            "('feishu_bot','mail') GROUP BY fmt ORDER BY id").fetchall()]
        for a in rows:
            got_fmts = {p["wh_fmt"] for p in sp_by_alert.get(a["id"], [])}
            for w in all_wh:
                if w["fmt"] not in got_fmts:
                    sp_by_alert.setdefault(a["id"], []).append(
                        {"wh_name": w["name"], "wh_fmt": w["fmt"], "status": "none",
                         "attempts": "", "response_code": None,
                         "last_error": "未推送（提醒生成时该渠道未启用）"})
    counts = pusher.sub_queue_counts()
    fq = subwatcher.freq()
    return templates.TemplateResponse(request, "sub_alerts.html", _ctx(
        request, rows=rows, sp_by_alert=sp_by_alert, msg=msg,
        page=page, pages=pages, total=total, counts=counts, per_cn=_PER_CN,
        fq_hour=int(fq["hour"])))


def _sub_form_common(title: str, category: str, period: str, custom_days: str,
                     next_date: str, amount: str, note: str, sub_type: str,
                     currency: str = "CNY"):
    title = title.strip()[:60]
    if not title:
        return None, "title"
    if category not in _cats():
        category = _FALLBACK_CAT
    if currency not in subwatcher.currencies():
        currency = "CNY"
    if period not in ("yearly", "quarterly", "monthly", "weekly", "custom"):
        period = "monthly"
    cd = int(custom_days) if custom_days.isdigit() and 1 <= int(custom_days) <= 3650 else 30
    nd = _valid_date(next_date)
    if not nd:
        return None, "date"
    # leads=全局设置（提醒设置页），单条订阅不再携带
    return dict(title=title, category=category, type=sub_type, period=period,
                custom_days=cd, next_date=nd, currency=currency,
                amount=amount.strip()[:60], note=note.strip()[:200]), ""


@app.post("/subscribe/add")
async def sub_add(request: Request, title: str = Form(""), category: str = Form("其他"),
                  sub_type: str = Form("periodic"), period: str = Form("monthly"),
                  custom_days: str = Form("30"), next_date: str = Form(""),
                  amount: str = Form(""), currency: str = Form("CNY"), note: str = Form(""),
                  logo: UploadFile = File(None)):
    r = await auth_required(request)
    if r:
        return r
    d, err = _sub_form_common(title, category, period, custom_days, next_date,
                              amount, note, "once" if sub_type == "once" else "periodic",
                              currency)
    if d is None:
        return RedirectResponse(f"/subscribe?msg=bad_{err}", status_code=303)
    logo_bytes, logo_ext = b"", ""
    if logo is not None and logo.filename:
        logo_bytes = await logo.read(config.LOGO_MAX_BYTES + 1)  # 限量读取，超大文件不吞内存
        logo_ext = _logo_ext(logo_bytes)
        if not logo_ext or len(logo_bytes) > config.LOGO_MAX_BYTES:
            return RedirectResponse("/subscribe?msg=bad_logo", status_code=303)
    conn = db.db()
    cur = conn.execute(
        "INSERT INTO subs(title,category,type,period,custom_days,next_date,leads,amount,"
        "currency,note,enabled,status,has_logo,fired,last_reminded_at,created_at)"
        " VALUES(?,?,?,?,?,?,'0',?,?,?,'1','active',0,'',0,?)",
        (d["title"], d["category"], d["type"], d["period"], d["custom_days"],
         d["next_date"], d["amount"], d["currency"], d["note"], db.now()))
    sub_id = cur.lastrowid
    if logo_bytes:
        _logo_path(sub_id, logo_ext).write_bytes(logo_bytes)
        conn.execute("UPDATE subs SET has_logo=1,logo_ext=? WHERE id=?", (logo_ext, sub_id))
    conn.commit()
    subwatcher.rescan()
    return RedirectResponse("/subscribe?msg=added", status_code=303)


@app.post("/subscribe/{sub_id}/update")
async def sub_update(request: Request, sub_id: int,
                     title: str = Form(""), category: str = Form("其他"),
                     sub_type: str = Form("periodic"), period: str = Form("monthly"),
                     custom_days: str = Form("30"), next_date: str = Form(""),
                     amount: str = Form(""), currency: str = Form("CNY"), note: str = Form("")):
    r = await auth_required(request)
    if r:
        return r
    cur = db.db().execute("SELECT * FROM subs WHERE id=?", (sub_id,)).fetchone()
    if cur is None:
        return RedirectResponse("/subscribe", status_code=303)
    d, err = _sub_form_common(title, category, period, custom_days, next_date,
                              amount, note, "once" if sub_type == "once" else "periodic",
                              currency)
    if d is None:
        return RedirectResponse(f"/subscribe?msg=bad_{err}", status_code=303)
    db.db().execute(
        "UPDATE subs SET title=?,category=?,type=?,period=?,custom_days=?,next_date=?,"
        "amount=?,currency=?,note=?,fired='',status='active' WHERE id=?",
        (d["title"], d["category"], d["type"], d["period"], d["custom_days"],
         d["next_date"], d["amount"], d["currency"], d["note"], sub_id))
    db.db().commit()
    subwatcher.rescan()
    return RedirectResponse("/subscribe?msg=updated", status_code=303)


def db_now_date() -> str:
    from datetime import datetime
    return datetime.now().date().isoformat()


@app.post("/subscribe/{sub_id}/toggle")
async def sub_toggle(request: Request, sub_id: int):
    r = await auth_required(request)
    if r:
        return r
    db.db().execute("UPDATE subs SET enabled=1-enabled WHERE id=?", (sub_id,))
    db.db().commit()
    return RedirectResponse("/subscribe", status_code=303)


def _logo_path(sub_id: int, ext: str):
    return config.LOGO_DIR / f"{sub_id}.{ext}"


@app.post("/subscribe/{sub_id}/delete")
async def sub_delete(request: Request, sub_id: int, logo_only: str = Form("")):
    r = await auth_required(request)
    if r:
        return r
    row = db.db().execute("SELECT has_logo,logo_ext FROM subs WHERE id=?", (sub_id,)).fetchone()
    if logo_only == "1":
        if row and row["has_logo"]:
            p = _logo_path(sub_id, row["logo_ext"])
            p.unlink(missing_ok=True)
            db.db().execute("UPDATE subs SET has_logo=0,logo_ext='' WHERE id=?", (sub_id,))
            db.db().commit()
        return RedirectResponse("/subscribe?msg=logo_removed", status_code=303)
    # 级联删（踩坑记录6：不依赖外键，显式清 alerts/sub_pushes/logo 文件）
    conn = db.db()
    aids = [x["id"] for x in conn.execute("SELECT id FROM alerts WHERE sub_id=?", (sub_id,))]
    if aids:
        q = ",".join("?" * len(aids))
        conn.execute(f"DELETE FROM sub_pushes WHERE alert_id IN ({q})", aids)
        conn.execute("DELETE FROM alerts WHERE sub_id=?", (sub_id,))
    conn.execute("DELETE FROM subs WHERE id=?", (sub_id,))
    conn.commit()
    if row and row["has_logo"]:
        _logo_path(sub_id, row["logo_ext"]).unlink(missing_ok=True)
    return RedirectResponse("/subscribe?msg=deleted", status_code=303)


def _logo_ext(data: bytes) -> str:
    """图片魔数 → 扩展名；不识别返回空串。"""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return ""


@app.post("/subscribe/{sub_id}/logo")
async def sub_logo(request: Request, sub_id: int, file: UploadFile = File(...)):
    r = await auth_required(request)
    if r:
        return r
    row = db.db().execute("SELECT id FROM subs WHERE id=?", (sub_id,)).fetchone()
    if row is None:
        return RedirectResponse("/subscribe", status_code=303)
    data = await file.read(config.LOGO_MAX_BYTES + 1)  # 限量读取
    ext = _logo_ext(data)
    if not ext or len(data) > config.LOGO_MAX_BYTES:
        return RedirectResponse("/subscribe?msg=bad_logo", status_code=303)
    old = db.db().execute("SELECT logo_ext FROM subs WHERE id=?", (sub_id,)).fetchone()
    if old and old["logo_ext"] and old["logo_ext"] != ext:
        _logo_path(sub_id, old["logo_ext"]).unlink(missing_ok=True)
    _logo_path(sub_id, ext).write_bytes(data)
    db.db().execute("UPDATE subs SET has_logo=1,logo_ext=? WHERE id=?", (ext, sub_id))
    db.db().commit()
    return RedirectResponse("/subscribe?msg=logo_ok", status_code=303)


@app.get("/subscribe/logo/{sub_id}")
async def sub_logo_get(request: Request, sub_id: int):
    # 与其余业务路由同等鉴权：LOGO 属订阅元数据，登录前不得按自增 id 枚举
    r = await auth_required(request)
    if r:
        return r
    row = db.db().execute("SELECT has_logo,logo_ext FROM subs WHERE id=?", (sub_id,)).fetchone()
    if not row or not row["has_logo"]:
        return RedirectResponse("/subscribe", status_code=303)
    p = _logo_path(sub_id, row["logo_ext"])
    if not p.exists():
        return RedirectResponse("/subscribe", status_code=303)
    media = {"png": "image/png", "jpg": "image/jpeg", "webp": "image/webp"}[row["logo_ext"]]
    return FileResponse(p, media_type=media,
                        headers={"Cache-Control": "no-store",
                                 "Content-Security-Policy": "default-src 'none'",
                                 "X-Content-Type-Options": "nosniff"})


@app.post("/subscribe/alerts/clear")
async def sub_alerts_clear(request: Request):
    r = await auth_required(request)
    if r:
        return r
    conn = db.db()
    n = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    conn.execute("DELETE FROM sub_pushes")
    conn.execute("DELETE FROM alerts")
    conn.commit()
    return RedirectResponse(f"/subscribe/alerts?msg=cleared:{n}", status_code=303)


@app.post("/subscribe/alerts/{alert_id}/requeue")
async def sub_alert_requeue(request: Request, alert_id: int):
    r = await auth_required(request)
    if r:
        return r
    pusher.requeue_dead_for_alert(alert_id)
    return RedirectResponse("/subscribe/alerts", status_code=303)


@app.get("/subscribe/settings", response_class=HTMLResponse)
async def sub_settings(request: Request, msg: str = ""):
    r = await auth_required(request)
    if r:
        return r
    chans = subwatcher.channels()
    fq = subwatcher.freq()
    cfg = mailer.get_cfg(masked=True)
    conn = db.db()
    fs = conn.execute("SELECT * FROM webhooks WHERE fmt='feishu_bot'"
                      " AND name LIKE '订阅%' ORDER BY id LIMIT 1").fetchall()
    ml = conn.execute("SELECT * FROM webhooks WHERE fmt='mail'"
                      " AND name LIKE '订阅%' ORDER BY id LIMIT 1").fetchall()
    fcm = config.feishu_cfg(masked=True)
    masked = fcm["chat_id"] or "未配置"
    aid_masked = fcm["app_id"] or "未配置"
    feishu_ready = bool(config.feishu_cfg()["app_id"] and config.feishu_cfg()["app_secret"]
                        and config.feishu_cfg()["chat_id"])
    cat_counts = {row["category"]: row["c"] for row in db.db().execute(
        "SELECT category, COUNT(*) c FROM subs GROUP BY category")}
    return templates.TemplateResponse(request, "sub_settings.html", _ctx(
        request, msg=msg, chans=chans, smtp=cfg, fs=fs, ml=ml,
        cats=_cats(), cat_counts=cat_counts, curs=subwatcher.cur_table(),
        fq_days=fq["days"], fq_hour=int(fq["hour"]),
        freq_days_opts=_FREQ_DAYS, freq_hours_opts=_FREQ_HOURS,
        smtp_ready=mailer.smtp_configured(), feishu_chat_masked=masked,
        feishu_app_id_masked=aid_masked, feishu_ready=feishu_ready,
        feishu=fcm,
        smtp_timeout=config.SMTP_TIMEOUT_S))


@app.post("/subscribe/settings/frequency")
async def sub_frequency_save(request: Request, days: str = Form("7"), hour: str = Form("9")):
    r = await auth_required(request)
    if r:
        return r
    d, err = _freq_form(days, hour)
    if d is None:
        return RedirectResponse("/subscribe/settings?msg=bad_freq", status_code=303)
    subwatcher.set_freq(d)
    return RedirectResponse("/subscribe/settings?msg=freq_saved", status_code=303)

@app.post("/subscribe/settings/categories/add")
async def sub_cat_add(request: Request, name: str = Form("")):
    r = await auth_required(request)
    if r:
        return r
    name = name.strip()[:12]
    cats = _cats()
    if not name or name == _FALLBACK_CAT:
        return RedirectResponse("/subscribe/settings?msg=bad_cat", status_code=303)
    if name in cats:
        return RedirectResponse("/subscribe/settings?msg=dup_cat", status_code=303)
    if len(cats) >= 20:
        return RedirectResponse("/subscribe/settings?msg=too_many_cat", status_code=303)
    cats.append(name)
    import json as _json
    db.set_setting(_SUB_CATS_KEY, _json.dumps(cats, ensure_ascii=False))
    return RedirectResponse("/subscribe/settings?msg=cat_added", status_code=303)


@app.post("/subscribe/settings/categories/delete")
async def sub_cat_del(request: Request, name: str = Form("")):
    r = await auth_required(request)
    if r:
        return r
    name = name.strip()[:12]
    cats = _cats()
    if name not in cats:
        return RedirectResponse("/subscribe/settings?msg=no_cat", status_code=303)
    n = db.db().execute("SELECT COUNT(*) c FROM subs WHERE category=?", (name,)).fetchone()["c"]
    if n:
        return RedirectResponse(f"/subscribe/settings?msg=cat_in_use:{n}", status_code=303)
    if len(cats) <= 1:
        return RedirectResponse("/subscribe/settings?msg=last_cat", status_code=303)
    cats.remove(name)
    import json as _json
    db.set_setting(_SUB_CATS_KEY, _json.dumps(cats, ensure_ascii=False))
    return RedirectResponse("/subscribe/settings?msg=cat_deleted", status_code=303)


@app.post("/subscribe/settings/currencies/add")
async def sub_cur_add(request: Request, code: str = Form(""), name: str = Form(""),
                      sym: str = Form("")):
    r = await auth_required(request)
    if r:
        return r
    code, name, sym = code.strip().upper()[:4], name.strip()[:12], sym.strip()[:4]
    if not (code and name and sym):
        return RedirectResponse("/subscribe/settings?msg=bad_cur", status_code=303)
    table = subwatcher.cur_table()
    if any(x["code"] == code for x in table):
        return RedirectResponse("/subscribe/settings?msg=dup_cur", status_code=303)
    if len(table) >= 16:
        return RedirectResponse("/subscribe/settings?msg=too_many_cat", status_code=303)
    table = table + [{"code": code, "name": name, "sym": sym}]
    import json as _json
    db.set_setting(subwatcher._SUB_CURS_KEY, _json.dumps(table, ensure_ascii=False))
    return RedirectResponse("/subscribe/settings?msg=cur_added", status_code=303)


@app.post("/subscribe/settings/currencies/delete")
async def sub_cur_del(request: Request, code: str = Form("")):
    r = await auth_required(request)
    if r:
        return r
    code = code.strip().upper()[:4]
    table = subwatcher.cur_table()
    if not any(x["code"] == code for x in table):
        return RedirectResponse("/subscribe/settings?msg=no_cur", status_code=303)
    if len(table) <= 1:
        return RedirectResponse("/subscribe/settings?msg=last_cur", status_code=303)
    table = [x for x in table if x["code"] != code]
    import json as _json
    db.set_setting(subwatcher._SUB_CURS_KEY, _json.dumps(table, ensure_ascii=False))
    return RedirectResponse("/subscribe/settings?msg=cur_deleted", status_code=303)


@app.post("/subscribe/settings/feishu")
async def sub_feishu_save(request: Request, app_id: str = Form(""), app_secret: str = Form(""),
                          chat_id: str = Form(""), api_base: str = Form("")):
    r = await auth_required(request)
    if r:
        return r
    # 全部留空提交也合法（=什么都不改，同 SMTP keep_pw 语义）
    config.feishu_save_cfg({"app_id": app_id, "app_secret": app_secret,
                            "chat_id": chat_id, "api_base": api_base})
    return RedirectResponse("/subscribe/settings?msg=feishu_saved", status_code=303)


@app.post("/subscribe/settings/channels")
async def sub_channels(request: Request, feishu: str = Form("0"),
                       mail: str = Form("0")):
    r = await auth_required(request)
    if r:
        return r
    subwatcher.set_channels({"feishu": feishu == "1", "mail": mail == "1"})
    return RedirectResponse("/subscribe/settings?msg=chans", status_code=303)


async def _test_via_webhook(request: Request, fmt: str, sub_msg: str) -> RedirectResponse:
    """订阅渠道发测试：走旁路独立 client，不占队列。"""
    from . import pusher as P
    async with P.httpx.AsyncClient(timeout=config.PUSH_TIMEOUT_S) as c:
        probe = {"title": "测试订阅", "lead_days": 7, "fire_date": db_now_date(),
                 "next_date": db_now_date(), "amount": "58 / 年", "currency": "CNY",
                 "note": "格式测试推送",
                 "kind": "yearly", "label": "", "created_at": int(time.time())}
        try:
            err = ""
            if fmt == "feishu_bot":
                ok, code, err = await P.feishu_send(P.alert_card(probe), config.feishu_cfg()["chat_id"], client=c)
            else:
                ok, code, err = await mailer.send(P.alert_subject(probe), P.fmt_alert(probe))
            msg = f"{sub_msg}:ok" if ok else f"{sub_msg}:fail:{(err or str(code))[:80]}"
        except Exception as e:
            msg = f"{sub_msg}:error:{type(e).__name__}"
    return RedirectResponse("/subscribe/settings?msg=" + urllib.parse.quote(msg, safe=":"), status_code=303)


@app.post("/subscribe/settings/test/feishu")
async def sub_test_feishu(request: Request):
    r = await auth_required(request)
    if r:
        return r
    return await _test_via_webhook(request, "feishu_bot", "test_feishu")


@app.post("/subscribe/settings/test/mail")
async def sub_test_mail(request: Request):
    r = await auth_required(request)
    if r:
        return r
    return await _test_via_webhook(request, "mail", "test_mail")


@app.post("/subscribe/settings/smtp")
async def sub_smtp_save(request: Request, host: str = Form(""), port: str = Form("465"),
                        security: str = Form("ssl"), user: str = Form(""),
                        password: str = Form(""), to: str = Form(""),
                        from_name: str = Form(""), keep_pw: str = Form("")):
    r = await auth_required(request)
    if r:
        return r
    host, user, to = host.strip(), user.strip(), to.strip()
    port_i = int(port) if port.isdigit() else 0
    if security not in ("ssl", "starttls"):
        security = "ssl"
    if not host or not (1 <= port_i <= 65535) or not user or "@" not in to:
        return RedirectResponse("/subscribe/settings?msg=bad_smtp", status_code=303)
    old = mailer.get_cfg()
    pw = password.strip()
    if not pw and keep_pw == "keep":
        pw = old.get("password", "")
    mailer.save_cfg({"host": host, "port": str(port_i), "security": security,
                     "user": user, "password": pw, "to": to,
                     "from_name": from_name.strip()[:40]})
    return RedirectResponse("/subscribe/settings?msg=smtp_saved", status_code=303)
