# 订阅提醒站（Subscribe Reminders）容器镜像
# 构建:  docker build -t sub-reminders .
# 运行:  docker run -d --name sub-reminders --restart unless-stopped \
#          -p 127.0.0.1:8766:8766 -v sub-data:/data -e SUB_HOST=0.0.0.0 sub-reminders
# ⚠️ 单副本纪律：调度器/推送器随进程起，**严禁多 worker/多实例双跑**（会双发提醒）。
FROM python:3.12-slim

# 时区=调度语义：提醒钟点/换日边界全按本地时区算，默认上海（改时区请同时改这里）
ENV TZ=Asia/Shanghai \
    PYTHONUNBUFFERED=1 \
    SUB_DATA_DIR=/data \
    SUB_LOG_STDOUT=1 \
    PIP_NO_CACHE_DIR=1

# tzdata：slim 基础镜像默认不带，datetime 本地化依赖它
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY subpanel/ subpanel/
COPY run_sub.py .

# 非 root 运行；/data 属主交给运行用户（挂 named volume 时首启会继承此属主）
RUN useradd -m -u 10001 app && mkdir -p /data && chown -R app:app /data /app
USER app
VOLUME /data

# SUB_HOST 必须 0.0.0.0 才能被容器外访问（安全默认 127.0.0.1 在容器里等于不可达）
ENV SUB_HOST=0.0.0.0
EXPOSE 8766

# 探活：走 /login 页（200=服务活着；鉴权开启时业务页会 303，不适合做探针）
HEALTHCHECK --interval=60s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8766/login', timeout=8).status==200 else 1)"

CMD ["python", "run_sub.py"]
