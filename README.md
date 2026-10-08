# Subscribe Reminders — 订阅提醒

订阅续费到期提醒站：周期项（年/季/月/周/每N天）+一次性项，全局频率**每日连催**（提前 1-7 天起每天一提直到到期当天），推送飞书卡片 / SMTP 邮件；订阅列表带 LOGO、金额货币、分类管理、提醒记录页。

本站是 My-Panel 拆分出的**独立网站**（:8766），与姊妹站 `../TG KeyWatch/`（关键字监控 :8765）零共用——各自 venv / .env / data / 文档。飞书凭据在**本库内**管理（设置页直接填，保存即生效）。

## 快速开始

```bash
cd "Subscribe Reminders"
.venv\Scripts\python run_sub.py      # 启动 http://127.0.0.1:8766
```

首次访问跳登录页，默认密码 `admin`（登录后到顶栏「改密」修改，改后存 DB；可用环境变量 `SUB_ADMIN_PASSWORD` 改默认值）。Linux 下用 `.venv/bin/python run_sub.py`。

## Docker 部署

```bash
docker build -t sub-reminders .
docker run -d --name sub-reminders --restart unless-stopped \
  -p 127.0.0.1:8766:8766 -v sub-data:/data \
  -e SUB_HOST=0.0.0.0 -e TZ=Asia/Shanghai sub-reminders
# 管理访问走 SSH 隧道：ssh -L 8766:127.0.0.1:8766 <vps>
```

compose 版——在源码仓库根目录建 `docker-compose.yml`，内容：

```yaml
services:
  sub-reminders:
    build: .
    image: sub-reminders:latest
    container_name: sub-reminders
    restart: unless-stopped
    ports:
      # 只绑宿主机 127.0.0.1：管理访问走 SSH 隧道，绝不公网 HTTP
      - "127.0.0.1:8766:8766"
    environment:
      SUB_AUTH_ENABLED: "1"     # 鉴权常开（容器语境默认值本就是 1，写明防误解）
      # SUB_ADMIN_PASSWORD: *** # 可选：改首启默认口令（默认 admin，改后存 DB）
      # SUB_COOKIE_SECURE: "1"  # https 反代场景开启
    volumes:
      - sub-data:/data          # 必须命名卷（SQLite WAL 对 bind mount 跨文件系统敏感）
    # ⚠️ 严禁 scale/多实例：调度+推送随进程起，双跑=提醒双发

volumes:
  sub-data:
```

```bash
docker compose up -d --build    # 构建镜像并起服务
docker compose logs -f          # 看运行日志（容器形态 INFO 直出 stdout）
docker compose down             # 停服（数据留在 sub-data 命名卷，不丢）
# 管理访问走 SSH 隧道：ssh -L 8766:127.0.0.1:8766 <vps>
```

要点：**镜像不含 data/.env**（.dockerignore 已挡），凭据只在命名卷里；时区=调度语义（Dockerfile 已默认上海）；**严禁多 worker/双实例**（调度+推送随进程起，双跑=提醒双发）；https 反代场景设 `SUB_COOKIE_SECURE=***

## 使用流程

1. 「订阅总览」：右上「＋ 添加订阅」弹窗——名称/下次到期日/周期(+每N天)/分类/金额+货币/备注/LOGO(可选)
2. 「设置」：提醒频率（提前 1-7 天 + 每天几点检查，全模块统一）、分类管理、币种管理、飞书机器人接入（App ID/Secret/Chat ID 存库、脱敏回显）、渠道开关+发测试、SMTP
3. 「提醒记录」：历史提醒与各渠道送达状态（✓/死信重推）、清除记录

## 关键约定

- 每天检查钟点一到自动扫描；**电脑关机/睡眠错过当天=那发作废记 skipped，次日连催继续**（要 24/7 请上 VPS，见 PROJECT_NOTES 待办）
- 到期日自动按日历推算下一期（短月钳月末）；手改日期=重新排期
- 分类下有订阅时不能删分类；「未分类」是代码回退位

## 安全

`data/subpanel.db` 含飞书 App Secret 与 SMTP 授权码明文——**敏感资产**，服务只绑 127.0.0.1，文件权限当钥匙管；错误回显过 `_scrub()`。

> 决策依据、UI 规格、踩坑、验证记录全部在 `PROJECT_NOTES.md`。
