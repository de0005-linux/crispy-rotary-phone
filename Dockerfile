FROM pasarguard/node:latest AS jinx-core
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATA_DIR=/data \
    PORT=8080 \
    LUMEN_PANEL_PORT=8000 \
    XRAY_EXECUTABLE_PATH=/usr/local/bin/xray \
    XRAY_ASSETS_PATH=/usr/local/share/xray

WORKDIR /app

# tini forwards Railway's termination signal to Python. gosu lets the
# entrypoint make the mounted /data volume writable before running the relay
# without root privileges.
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates gosu tini nginx \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 lumen \
    && useradd --uid 10001 --gid lumen --create-home --home-dir /app lumen \
    && install -d --owner=lumen --group=lumen --mode=0700 /data


COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY --chown=lumen:lumen . /app
COPY --from=jinx-core /usr/local/bin/xray /usr/local/bin/xray
COPY --from=jinx-core /usr/local/share/xray /usr/local/share/xray
COPY nginx.conf.template /etc/nginx/nginx.conf.template
RUN chmod 0755 /app/docker-entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--", "/app/docker-entrypoint.sh"]
CMD ["python", "main.py"]