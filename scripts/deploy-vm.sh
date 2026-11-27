#!/usr/bin/env bash
# Deploy Tributary to a VM over SSH: pull, build, install the service, restart, health-check.
#
#   scripts/deploy-vm.sh <ssh-host> [git-ref]
#
# Needs on the VM: git, Node 20+, pnpm, ffmpeg, and sudo for systemctl.
# The data directory (recordings, transcripts, the SQLite database) is never touched by a deploy.
# HTTPS is not set up here: point a reverse proxy or Cloudflare tunnel at http://localhost:4100
# (see docs/DEPLOYMENT.md). Browsers only allow camera and microphone over HTTPS.
set -euo pipefail

HOST="${1:?usage: deploy-vm.sh <ssh-host> [git-ref]}"
REF="${2:-main}"
SSH_USER="${TRIBUTARY_SSH_USER:-pipeline}"
APP_DIR="${TRIBUTARY_APP_DIR:-/home/$SSH_USER/tributary}"
DATA_DIR="${TRIBUTARY_DATA_DIR:-/var/lib/tributary}"
REPO="${TRIBUTARY_REPO:-git@github.com:lbruce67/tributary.git}"

ssh "$SSH_USER@$HOST" APP_DIR="$APP_DIR" DATA_DIR="$DATA_DIR" REPO="$REPO" REF="$REF" SVC_USER="$SSH_USER" 'bash -s' <<'REMOTE'
set -euo pipefail
for bin in git node pnpm ffmpeg; do
  command -v "$bin" >/dev/null || { echo "missing on this VM: $bin" >&2; exit 1; }
done
node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)' || { echo "Node 20 or newer is required" >&2; exit 1; }

[ -d "$APP_DIR/.git" ] || git clone "$REPO" "$APP_DIR"
cd "$APP_DIR"
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "Uncommitted changes in $APP_DIR; refusing to overwrite them. Commit or stash them first." >&2
  exit 1
fi
git fetch --prune origin
git checkout "$REF"
git pull --ff-only origin "$REF" 2>/dev/null || true   # a tag or commit has nothing to pull
pnpm install --frozen-lockfile
pnpm build

sudo mkdir -p "$DATA_DIR" /etc/tributary
sudo chown "$SVC_USER" "$DATA_DIR"
if [ ! -f /etc/tributary/tributary.env ]; then
  printf 'TRIBUTARY_DATA_DIR=%s\n' "$DATA_DIR" | sudo tee /etc/tributary/tributary.env >/dev/null
  sudo chmod 640 /etc/tributary/tributary.env
  sudo chown "root:$SVC_USER" /etc/tributary/tributary.env
fi
sed -e "s|__USER__|$SVC_USER|" -e "s|__DIR__|$APP_DIR|" deploy/tributary.service | sudo tee /etc/systemd/system/tributary.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable tributary >/dev/null
sudo systemctl restart tributary

for _ in $(seq 1 30); do
  if curl -fsS -o /dev/null http://localhost:4100/; then
    echo "Tributary is serving on http://localhost:4100 at $(git rev-parse --short HEAD)"
    exit 0
  fi
  sleep 1
done
echo "Tributary did not answer on port 4100. Last log lines:" >&2
sudo journalctl -u tributary -n 40 --no-pager >&2
exit 1
REMOTE
