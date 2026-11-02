#!/usr/bin/env bash
# Build the static app locally and ship it to the host. Requires deploy/.env on the host (TS_AUTHKEY).
#   deploy/push.sh [ssh-host] [remote-dir]
set -euo pipefail
HOST=${1:-bluedragon}
DIR=${2:-/home/bluedragon/recon}
cd "$(dirname "$0")/.."
# the published export must be the masked one
grep -q '"ips_masked":true' web/public/data/accounts.json || { echo "export is not IP-masked; refusing"; exit 1; }
(cd web && npm run build)
ssh "$HOST" "mkdir -p $DIR/site"
rsync -az --delete web/dist/ "$HOST:$DIR/site/"
rsync -az deploy/compose.yaml deploy/compose.tailscale.yaml deploy/tailscale-serve.json deploy/nginx.conf "$HOST:$DIR/"
ssh "$HOST" "cd $DIR && test -f .env && docker compose -f compose.yaml -f compose.tailscale.yaml up -d && docker compose -f compose.yaml -f compose.tailscale.yaml ps"
