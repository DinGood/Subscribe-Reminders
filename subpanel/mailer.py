"""邮件通道：SMTP 配置全存 DB settings 表（后台可改），授权码只以 **** 回显、绝不外泄。
smtplib 是阻塞库，一律 asyncio.to_thread 下跑；SSL465 或 STARTTLS587 两种加密。
出站一律直连（本站无需代理）。"""
import asyncio
import json
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.utils import formataddr

from . import config, db

_KEY = "smtp_cfg"
_pw_cache: tuple[str, float] = ("", 0.0)  # 授权码明文短 TTL 缓存（改动处失效），防进 DB 缓存串


def _load() -> dict:
    raw = db.get_setting(_KEY)
    if not raw:
        return {}
    try:
        d = json.loads(raw)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def smtp_configured() -> bool:
    try:
        c = _load()
    except Exception:
        return False
    host, user, pw = c.get("host", ""), c.get("user", ""), c.get("password", "")
    return bool(host and user and pw and c.get("to", ""))


def get_cfg(masked: bool = False) -> dict:
    """读配置；masked=True 时授权码只回显 ****。"""
    c = _load()
    if masked:
        c = dict(c)
        c["password"] = "****" if c.get("password") else ""
    return c


def save_cfg(d: dict) -> None:
    old = _load()
    pw = (d.get("password") or "").strip()
    if not pw:  # 空提交 = 保持已存授权码（页面回显是 ****）
        d["password"] = old.get("password", "")
    db.set_setting(_KEY, json.dumps(d, ensure_ascii=False))
    global _pw_cache
    _pw_cache = ("", 0.0)


def _password_plain() -> str:
    global _pw_cache
    if _pw_cache[0] and _pw_cache[1] > time.time():
        return _pw_cache[0]
    try:
        pw = _load().get("password", "")
    except Exception:
        pw = ""
    _pw_cache = (pw, time.time() + config.CFG_CACHE_TTL_S)
    return pw


def _send_direct(subject: str, body: str, cfg: dict) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((cfg.get("from_name") or cfg["user"], cfg["user"]))
    msg["To"] = cfg["to"]
    msg.set_content(body)
    host, port = cfg["host"], int(cfg.get("port") or 465)
    if cfg.get("security", "ssl") == "starttls":
        with smtplib.SMTP(host, port, timeout=config.SMTP_TIMEOUT_S) as s:
            s.starttls(context=ssl.create_default_context())
            s.login(cfg["user"], _password_plain())
            s.send_message(msg)
    else:
        with smtplib.SMTP_SSL(host, port, timeout=config.SMTP_TIMEOUT_S,
                              context=ssl.create_default_context()) as s:
            s.login(cfg["user"], _password_plain())
            s.send_message(msg)


def _send_blocking(subject: str, body: str, cfg: dict) -> tuple[bool, str]:
    try:
        _send_direct(subject, body, cfg)
        return True, ""
    except Exception as e1:
        return False, f"{type(e1).__name__}: {e1}"[:200]


async def send(subject: str, body: str) -> tuple[bool, int, str]:
    """async 入口（pusher worker 用）。返回 (ok, http码恒0=非HTTP, err)，err 过 _scrub。"""
    from . import pusher
    cfg = get_cfg()
    if not smtp_configured():
        return False, 0, pusher._scrub("SMTP 未配置（设置页填主机/账号/授权码/收件邮箱）")
    ok, err = await asyncio.to_thread(_send_blocking, subject, body, cfg)
    return ok, 0, pusher._scrub(err) if err else ""
