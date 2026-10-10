# Subscribe Reminders — 订阅提醒

订阅续费到期提醒站：周期项（年/季/月/周/每N天）+ 一次性项，全局频率**每日连催**（提前 1-7 天起每天一提，直到到期当天），推送**飞书卡片 / SMTP 邮件**。单进程 FastAPI + 单个 SQLite 文件，零外部依赖，开箱即 Docker 化。

功能：订阅卡片列表（LOGO、金额+币种、分类管理）· 续费网站外链（填了链接的订阅，单击名称新窗口直达续费页）· 行内编辑 + **一键续期**（续费完成后到期日按周期一键推进）· 提醒记录页（送达状态/死信重推）· 登录防暴力 + CSRF。飞书/SMTP 凭据存库内，设置页填写即生效。

## 快速开始

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt        # Windows: .venv\Scripts\pip
.venv/bin/python run_sub.py                      # Windows: .venv\Scripts\python → http://127.0.0.1:8766
```

首次访问跳登录页，默认密码 `admin`（登录后经顶栏「后台管理」修改，改后存库；可用环境变量 `SUB_ADMIN_PASSWORD` 改默认值）。

## Docker 部署

直接拉公开镜像（GHCR，匿名可拉，无需登录）：

```yaml
services:
  sub-reminders:
    image: ghcr.io/dingood/subscribe-reminders:1.0.5   # 或 :latest
    container_name: sub-reminders
    restart: unless-stopped
    user: "0"                     # 群晖 NAS 必加（免 chown）；其他宿主可去
    ports:
      - "8766:8766"               # 内网自用；公网机器请只绑 127.0.0.1 走 SSH 隧道
    volumes:
      - ./data:/data              # 目录绑定即可；升级换 tag，数据不动
```

```bash
docker compose up -d              # 起服务；docker compose logs -f 看运行日志
```

要本地自构建：`docker build -t sub-reminders .` 后把 image 改成 `sub-reminders` 即可（正式镜像由 CI 构建推 GHCR，见 `.github/workflows`）。

### 部署要点

- **严禁多 worker / 双实例**：调度与推送随进程起，双跑 = 提醒双发
- 镜像不含 `data/`/`.env`（`.dockerignore` 强制）；凭据只存在挂载卷的 SQLite 里——**数据库含飞书 Secret / SMTP 授权码明文，按敏感资产保管**
- 时区 = 调度语义：镜像默认 `Asia/Shanghai`，改时区需同步改 compose 的 `TZ`
- https 反代场景设 `SUB_COOKIE_SECURE=1`；局域网 IP 访问原生支持

## 使用流程

1. **订阅总览** → 右上「＋ 添加订阅」：名称/到期日/类型/周期(+每N天)/分类/金额+币种必填（红 `*`），续费网站/备注/LOGO 选填
2. 续费完成后在该行点「编辑」展开，再点 **「⟳ 一键续期」**：到期日按本订阅周期自动推进一期，提醒随之重排
3. **设置**：提醒频率（提前 1-7 天 + 每天几点检查，全模块统一）、分类/币种管理、飞书机器人接入、渠道开关 + 发测试、SMTP
4. **提醒记录**：每条提醒的渠道送达状态（✓ 已送达 / 待推 / 死信可重推），支持一键清除

## 关键行为

- 到期日自动按日历推算下一期（短月钳月末，如 1/31 → 2/28）；手改日期 = 重新排期
- 关机/睡眠错过当天钟点：服务醒来即补发；整天错过 = 那发作废（记录标「已作废」，不追发）——需要 24/7 常驻请部署在常开设备（NAS/服务器）
- 推送渠道独立开关（飞书/邮件），停用渠道在提醒生成时不入队
- 分类下还有订阅时不能删；币种删除不影响历史记录里的金额快照

## 开发

`tests/` 四套回归（鉴权流 / 调度离线断言 / 外链+必填+续期 E2E / SVG 净化），拉起服务后 `python tests/test_auth_flow.py` 等逐个跑即可。

## 许可

[MIT](LICENSE) — 随便用、改、再分发，保留版权声明即可；软件按「现状」提供，不承担任何担保责任。
