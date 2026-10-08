"""订阅提醒站入口：uvicorn + 同进程订阅调度。"""
import os
import logging
from logging.handlers import RotatingFileHandler
import uvicorn
from subpanel import config, web

_fmt = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
_root = logging.getLogger()
_root.setLevel(logging.INFO)
# 落盘走轮转：5MB × 2 备份封顶 ~15MB，旧日志自动滚出（诊断价值>历史流水）。
# ★ 启动约定（2026-10-03 起，仅 Windows 本机语境）：进程 stderr 必须重定向到
#   server.err.log，**不得**再指回 server.log —— Windows 上 Rename 需要句柄带
#   FILE_SHARE_DELETE，stderr 的追加句柄会让 rollover 直接 Access Denied，
#   且会造成 INFO 双写。server.log 由本 handler 唯一写入者持有。
# ★ 容器形态（SUB_LOG_STDOUT=1）：跳过文件 handler，INFO 直上 stdout（docker logs），
#   避免在易失容器文件系统里滚存+双写。
_stdout_mode = os.environ.get("SUB_LOG_STDOUT", "").strip() in ("1", "true", "yes")
if not _stdout_mode:
    _fh = RotatingFileHandler(config.DATA_DIR / "server.log", maxBytes=5_000_000,
                              backupCount=2, encoding="utf-8")
    _fh.setFormatter(_fmt)
    _root.addHandler(_fh)
_console = logging.StreamHandler()
_console.setLevel(logging.INFO if _stdout_mode else logging.WARNING)
_console.setFormatter(_fmt)
_root.addHandler(_console)
# httpx INFO 会打印完整 URL —— Telegram 推送 URL 内嵌 bot token，必须静音
logging.getLogger("httpx").setLevel(logging.WARNING)

if __name__ == "__main__":
    uvicorn.run(web.app, host=config.HOST, port=config.PORT, log_level="warning")
