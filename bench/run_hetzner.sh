#!/usr/bin/env bash
# bench/run_hetzner.sh — fully automated bench run on a fresh Hetzner CCX13.
#
# Runs on your Mac. Creates a server, rsyncs the LOCAL working copy (no need
# to commit/push first), runs the bench suite, downloads the output, deletes
# the server. End-to-end about 6-8 minutes; cost a few euro cents.
#
# Prereqs (one-time):
#   1. brew install hcloud
#   2. In Hetzner Cloud Console -> Security -> API Tokens, create a token
#      with Read & Write scope.
#   3. hcloud context create chiplog
#         (paste the token when prompted)
#   4. Upload your SSH public key once:
#         hcloud ssh-key create \
#             --name "$(whoami)-mac" \
#             --public-key-from-file ~/.ssh/id_ed25519.pub
#      (skip if you already have a key uploaded; `hcloud ssh-key list` to check)
#
# Run from the repo root:
#   bash bench/run_hetzner.sh
#
# Output (in current dir):
#   bench-hetzner.txt          human-readable pytest output
#   bench-hetzner.json         machine-readable for the BENCHMARKS.md matrix
#   bench-fingerprint.txt      hardware + storage + Python info

set -euo pipefail

LOCAL_REPO="${LOCAL_REPO:-$(pwd)}"
SSH_KEY_NAME="${SSH_KEY_NAME:-}"
SERVER_TYPE="${SERVER_TYPE:-ccx13}"
LOCATION="${LOCATION:-nbg1}"
IMAGE="${IMAGE:-ubuntu-24.04}"
NAME="bench-rig-$(date -u +%Y%m%dT%H%M%SZ)"

IP=""
cleanup() {
    # Always attempt delete by name — covers the case where Ctrl-C interrupts
    # `hcloud server create` after the server has been provisioned but before
    # the IP was captured locally.
    if hcloud server describe "$NAME" >/dev/null 2>&1; then
        echo
        echo "==> Cleaning up server $NAME"
        hcloud server delete "$NAME" >/dev/null 2>&1 \
            || echo "WARN: server delete failed; run 'hcloud server list' and clean up manually."
    fi
}
trap cleanup EXIT INT TERM

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: $1 not found in PATH"
        exit 1
    }
}
require hcloud
require ssh
require scp
require rsync

if [ ! -f "$LOCAL_REPO/pyproject.toml" ] \
   || ! grep -q '^name = "chiplog"' "$LOCAL_REPO/pyproject.toml"; then
    echo "ERROR: $LOCAL_REPO does not look like the chiplog repo."
    echo "Either cd to the repo root or set LOCAL_REPO=/abs/path."
    exit 1
fi

if [ -z "$SSH_KEY_NAME" ]; then
    SSH_KEY_NAME="$(hcloud ssh-key list -o columns=name -o noheader 2>/dev/null | head -n1 || true)"
    if [ -z "$SSH_KEY_NAME" ]; then
        echo "ERROR: no SSH keys uploaded to Hetzner. Upload one first:"
        echo "    hcloud ssh-key create --name \"\$(whoami)-mac\" --public-key-from-file ~/.ssh/id_ed25519.pub"
        exit 1
    fi
fi
echo "==> Hetzner SSH key: $SSH_KEY_NAME"

echo "==> Creating $SERVER_TYPE @ $LOCATION (name: $NAME)"
echo "    hcloud will print 'Waiting for create_server / start_server' for"
echo "    30-60 seconds while Hetzner boots the VM. This is normal — do NOT"
echo "    Ctrl-C here, the trap can't clean up a half-created server."
hcloud server create \
    --name "$NAME" \
    --type "$SERVER_TYPE" \
    --image "$IMAGE" \
    --location "$LOCATION" \
    --ssh-key "$SSH_KEY_NAME"
IP="$(hcloud server ip "$NAME")"
echo "==> Server IP: $IP"

echo "==> Waiting for SSH (up to 2 min)"
for i in $(seq 1 60); do
    if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
           -o ConnectTimeout=5 -o BatchMode=yes \
           "root@$IP" 'echo ok' >/dev/null 2>&1; then
        echo "    ready after $((i * 2))s"
        break
    fi
    sleep 2
    if [ "$i" = 60 ]; then
        echo "ERROR: SSH never came up"
        exit 1
    fi
done

echo "==> Syncing local working copy -> server"
rsync -aH \
    --exclude '.venv/' --exclude '__pycache__/' --exclude '*.pyc' \
    --exclude '.pytest_cache/' --exclude '.mypy_cache/' --exclude '.ruff_cache/' \
    --exclude '.git/' --exclude 'audit/' \
    --exclude 'bench-hetzner.*' --exclude 'bench-m2.*' --exclude 'bench-fingerprint.txt' \
    -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
    "$LOCAL_REPO/" "root@$IP:/root/chiplog/"

echo "==> Installing deps + running benches on remote (4-6 min)"
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "root@$IP" 'bash -s' <<'REMOTE'
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl build-essential >/dev/null
if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null
fi
export PATH="$HOME/.local/bin:$PATH"
cd /root/chiplog
uv sync --group dev
{
    echo "# Bench run $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "## Hardware"
    echo "CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
    echo "Cores: $(grep -c '^processor' /proc/cpuinfo)"
    echo "Memory: $(free -h | awk '/^Mem:/ {print $2}')"
    echo "Kernel: $(uname -srv)"
    echo
    echo "## Storage"
    df -T /root | tail -n +1
} > bench-fingerprint.txt
echo
echo "==> Running benches"
uv run pytest bench/ \
    --benchmark-only \
    --benchmark-columns=mean,stddev,ops,rounds \
    --benchmark-sort=mean \
    --benchmark-json=bench-hetzner.json \
    | tee bench-hetzner.txt
REMOTE

echo
echo "==> Downloading results"
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "root@$IP:/root/chiplog/bench-hetzner.txt" \
    "root@$IP:/root/chiplog/bench-hetzner.json" \
    "root@$IP:/root/chiplog/bench-fingerprint.txt" \
    ./

echo
echo "==> Done. Files in $(pwd):"
ls -lh bench-hetzner.txt bench-hetzner.json bench-fingerprint.txt
