"""SQLite 层：schema + 通用访问。单进程内同步 sqlite3（WAL）。订阅域表。"""
import sqlite3
import time
import threading
from . import config

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webhooks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  url TEXT NOT NULL,
  fmt TEXT NOT NULL DEFAULT 'generic',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS subs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT '其他',
  type TEXT NOT NULL DEFAULT 'periodic',
  period TEXT NOT NULL DEFAULT 'monthly',
  custom_days INTEGER NOT NULL DEFAULT 0,
  next_date TEXT NOT NULL,
  leads TEXT NOT NULL DEFAULT '0',
  amount TEXT NOT NULL DEFAULT '',
  currency TEXT NOT NULL DEFAULT 'CNY',
  note TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active',
  has_logo INTEGER NOT NULL DEFAULT 0,
  logo_ext TEXT NOT NULL DEFAULT '',
  fired TEXT NOT NULL DEFAULT '',
  last_reminded_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sub_id INTEGER NOT NULL REFERENCES subs(id) ON DELETE CASCADE,
  title TEXT NOT NULL DEFAULT '',
  lead_days INTEGER NOT NULL DEFAULT 0,
  fire_date TEXT NOT NULL DEFAULT '',
  next_date TEXT NOT NULL DEFAULT '',
  amount TEXT NOT NULL DEFAULT '',
  currency TEXT NOT NULL DEFAULT 'CNY',
  note TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL DEFAULT 'periodic',
  label TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  UNIQUE(sub_id, fire_date, lead_days)
);
CREATE TABLE IF NOT EXISTS sub_pushes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  webhook_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  response_code INTEGER,
  updated_at INTEGER NOT NULL,
  UNIQUE(alert_id, webhook_id)
);
CREATE INDEX IF NOT EXISTS idx_subpushes_due ON sub_pushes(status, next_attempt_at);
"""


def db() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return conn


def init_db() -> None:
    db().executescript(SCHEMA)
    # 轻量列迁移：老库补新列（CREATE IF NOT EXISTS 不会给存量表加列）
    cols = {r["name"] for r in db().execute("PRAGMA table_info(subs)")}
    if "url" not in cols:
        # 并发首启竞态（双进程共享卷）：后进者 ALTER 会撞 duplicate column，列已在 SCHEMA，忽略即可
        try:
            db().execute("ALTER TABLE subs ADD COLUMN url TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass
    db().commit()


def now() -> int:
    return int(time.time())


def get_setting(key: str, default: str = "") -> str:
    row = db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    conn = db()
    conn.execute(
        "INSERT INTO settings(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    conn.commit()
