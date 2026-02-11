#!/usr/bin/env bash
set -euo pipefail

dnf -y install podman >/dev/null
id -u appsvc &>/dev/null || useradd -m appsvc

cat >/opt/training/stage08_container_run.sh <<'RUN'
#!/usr/bin/env bash
# INTENTIONAL: --privileged kullanımı bilerek bırakıldı.
podman run --rm --privileged -p 127.0.0.1:5000:5000 docker.io/library/nginx:alpine
RUN
chmod +x /opt/training/stage08_container_run.sh
chown appsvc:appsvc /opt/training/stage08_container_run.sh
