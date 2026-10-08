# Subscribe Reminders — 订阅提醒

订阅续费到期提醒站：周期项（年/季/月/周/每N天）+一次性项，全局频率**每日连催**（提前 1-7 天起每天一提直到到期当天），推送飞书卡片 / SMTP 邮件；订阅列表带 LOGO、金额货币、分类管理、提醒记录页。

单进程 FastAPI 应用，数据全在一个 SQLite 文件里，无外部数据库/消息队列依赖，可直接 Docker 化部署。飞书凭据在**本库内**管理（设置页直接填，保存即生效）。

## 快速开始

```bash
cd "Subscribe Reminders"
.venv\Scripts\python run_sub.py      # 启动 http://127.0.0.1:8766
```

首次访问跳登录页，默认密码 `admin`（登录后到顶栏「改密」修改，改后存 DB；可用环境变量 `SUB_ADMIN_PASSWORD` 改默认值）。Linux 下用 `.venv/bin/python run_sub.py`。

## Docker 部署

**推荐：直接拉公开镜像**（GHCR，匿名可拉，无需登录）：

```bash
docker pull ghcr.io/dingood/subscribe-reminders:latest   # 或钉版本 :1.0.0
```

compose 引用：

```yaml
services:
  sub-reminders:
    image: ghcr.io/dingood/subscribe-reminders:latest    # 全小写；版本标签形如 1.0.0
    container_name: sub-reminders
    restart: unless-stopped
    ports:
      - "8766:8766"        # NAS/内网自用；公网机器请只绑 127.0.0.1 并走 SSH 隧道
    volumes:
      - /volume1/docker/sub-reminders:/data   # 数据目录需 chown 10001:10001（容器内非 root 用户）
```

本机自 build 亦可：

```bash
docker build -t sub-reminders .
docker run -d --name sub-reminders --restart unless-stopped \
  -p 127.0.0.1:8766:8766 -v sub-data:/data \
  -e SUB_HOST=0.0.0.0 -e TZ=Asia/Shanghai sub-reminders
# 管理访问走 SSH 隧道：ssh -L 8766:127.0.0.1:8766 <vps>
```

```bash
docker compose up -d            # 拉镜像并起服务（本地自 build 则加 --build）
docker compose logs -f          # 看运行日志（容器形态 INFO 直出 stdout）
docker compose down             # 停服（数据在挂载卷里，不丢）
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
