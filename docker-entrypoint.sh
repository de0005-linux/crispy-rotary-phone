#!/bin/sh
# Railway mounts the persistent volume at /data. Prepare only that dedicated
# application-state path, then run the relay as an unprivileged user.
set -eu

if [ "$(id -u)" = "0" ]; then
    mkdir -p /data
    chown -R lumen:lumen /data
    python /app/jinx_core.py paths
    cat >/etc/nginx/ws.inc <<'EOF'
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_set_header Host $host;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_buffering off;
proxy_read_timeout 1h;
EOF
    sed 's/__PORT__/8080/g' /etc/nginx/nginx.conf.template >/etc/nginx/nginx.conf
    nginx -t
    nginx
    exec gosu lumen env PORT=8000 LUMEN_PANEL_PORT=8000 "$@"
fi

exec "$@"