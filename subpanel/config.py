import os
from pathlib import Path
from datetime import timedelta  # noqa: F401  subwatcher 经 config.timedelta 使用
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent  # Subscribe Reminders/（站点根）
load_dotenv(BASE_DIR / ".env")

DATA_DIR = Path(os.environ.get("SUB_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "subpanel.db"

AUTH_ENABLED = os.environ.get("SUB_AUTH_ENABLED", "1").strip() != "0"
ALLOWED_HOSTS = {x.strip().lower() for x in os.environ.get("SUB_ALLOWED_HOSTS", "").split(",") if x.strip()}
HOST = os.environ.get("SUB_HOST", "127.0.0.1")
PORT = int(os.environ.get("SUB_PORT", "8766"))

# 飞书应用机器人（与 Hermes 网关同一应用，主动推消息到指定会话）
FEISHU_APP_ID = os.environ.get("FEISHU_APP_ID", "").strip()
FEISHU_APP_SECRET = os.environ.get("FEISHU_APP_SECRET", "").strip()
FEISHU_CHAT_ID = os.environ.get("FEISHU_CHAT_ID", "").strip()
FEISHU_API_BASE = os.environ.get("FEISHU_API_BASE", "https://open.feishu.cn")


FEISHU_CFG_KEY = "feishu_cfg"  # 库内配置优先，空项回退 .env（保存留空=不改）


def feishu_cfg(masked: bool = False) -> dict:
    """飞书凭证读取唯一入口：DB settings.feishu_cfg 逐字段覆盖 .env 默认。"""
    import json
    from . import db  # 懒加载避免循环（db 模块级 import config）
    out = {"app_id": FEISHU_APP_ID, "app_secret": FEISHU_APP_SECRET,
           "chat_id": FEISHU_CHAT_ID, "api_base": FEISHU_API_BASE}
    raw = db.get_setting(FEISHU_CFG_KEY)
    if raw:
        try:
            d = json.loads(raw)
            for k in ("app_id", "app_secret", "chat_id", "api_base"):
                v = str(d.get(k, "")).strip()
                if v:
                    out[k] = v
        except Exception:
            pass
    if masked:
        out = dict(out)
        out["app_secret"] = "****" if out["app_secret"] else ""
        a = out["app_id"]
        out["app_id"] = (a[:8] + "…" + a[-3:]) if len(a) > 12 else a
        c = out["chat_id"]
        out["chat_id"] = (c[:6] + "…" + c[-4:]) if len(c) > 12 else c
    return out


def feishu_save_cfg(d: dict) -> None:
    """空字段=保留已存值；存库后即时生效（读侧每次走 feishu_cfg()）。"""
    import json
    from . import db
    old = {}
    raw = db.get_setting(FEISHU_CFG_KEY)
    if raw:
        try:
            old = json.loads(raw)
        except Exception:
            old = {}
    merged = dict(old)
    for k in ("app_id", "app_secret", "chat_id", "api_base"):
        v = (d.get(k) or "").strip()
        if v:
            merged[k] = v
    db.set_setting(FEISHU_CFG_KEY, json.dumps(merged, ensure_ascii=False))

# 运行参数
PUSH_BACKOFF_S = [60, 300, 900]
PUSH_MAX_ATTEMPTS = 1 + len(PUSH_BACKOFF_S)
PUSH_TIMEOUT_S = 10.0
PUSH_POLL_INTERVAL_S = 5.0
CFG_CACHE_TTL_S = 5
SMTP_TIMEOUT_S = float(os.environ.get("SUB_SMTP_TIMEOUT", "15"))
COOKIE_SECURE = os.environ.get("SUB_COOKIE_SECURE", "").strip() in ("1", "true", "yes")
SUB_FIRE_MIN = 0
LOGO_DIR = DATA_DIR / "logos"
LOGO_DIR.mkdir(parents=True, exist_ok=True)
LOGO_MAX_BYTES = 200 * 1024
