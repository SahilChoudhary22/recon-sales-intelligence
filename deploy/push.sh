#!/usr/bin/env bash
# Build the app locally and ship it, the API code and the current serving store to the host.
# Requires deploy/.env on the host (TS_AUTHKEY).
#   deploy/push.sh [ssh-host] [remote-dir]
set -euo pipefail
HOST=${1:-bluedragon}
DIR=${2:-/home/bluedragon/recon}
cd "$(dirname "$0")/.."
STORE=data/serve/current
BUILD=$(readlink "$STORE")
# the published store must be the masked one (export.py also refuses to write an unmasked one)
grep -q '"ips_masked": true' "$STORE/meta.json" || { echo "serving store is not IP-masked; refusing"; exit 1; }
(cd web && npm run build)
ssh "$HOST" "mkdir -p $DIR/site $DIR/serve $DIR/api $DIR/web/src $DIR/app-data"
# the sign-in user: a name and a password hash (uv run python -m api.workspace hash), kept only in the host's
# .env; deploy/.env.recon (gitignored) holds the line to add on the first deploy
if ! ssh "$HOST" "grep -q '^RECON_USERS=' $DIR/.env"; then
  [ -f deploy/.env.recon ] || { echo "add RECON_USERS to $DIR/.env (uv run python -m api.workspace hash)"; exit 1; }
  ssh "$HOST" "cat >> $DIR/.env" < deploy/.env.recon
fi
rsync -az --delete web/dist/ "$HOST:$DIR/site/"
rsync -az --delete api/ "$HOST:$DIR/api/" --exclude __pycache__ --exclude bench.py
rsync -az web/src/catalog.json "$HOST:$DIR/web/src/"
# ship the build folder first, then move the pointer: the API never sees a half-copied build
rsync -az "data/serve/$BUILD/" "$HOST:$DIR/serve/$BUILD/"
ssh "$HOST" "cd $DIR/serve && ln -sfn $BUILD current.new && mv -T current.new current"
rsync -az deploy/compose.yaml deploy/compose.tailscale.yaml deploy/tailscale-serve.json deploy/nginx.conf deploy/api.Dockerfile "$HOST:$DIR/"
ssh "$HOST" "cd $DIR && test -f .env && docker compose -f compose.yaml -f compose.tailscale.yaml up -d --build && docker compose -f compose.yaml -f compose.tailscale.yaml ps"
