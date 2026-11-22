#!/bin/bash
# Gives the NetMind server the two privileges it needs WITHOUT running it as root.
#
#   scripts/setup-permissions.sh            install   (asks for your sudo password once)
#   scripts/setup-permissions.sh --remove   undo it
#
# 1. ARP scanning needs a raw socket (CAP_NET_RAW). The project venv gets a private copy of
#    its Python, named python-netmind, with only that capability. `make run` uses it when present.
# 2. Re-attaching a device after power-on needs root. Instead of a broad sudo rule, one small
#    validated command (scripts/netmind-reconnect) is allowed, for your user only.
# Run it as your normal user, from anywhere inside the repository.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER=/usr/local/sbin/netmind-reconnect
SUDOERS=/etc/sudoers.d/netmind

if [ "$(id -u)" -eq 0 ]; then
    echo "Run this as your normal user (it calls sudo itself), not as root." >&2
    exit 1
fi
USER_NAME="$(id -un)"
[[ "$USER_NAME" =~ ^[a-z_][a-z0-9_-]*$ ]] || { echo "Unusual user name '$USER_NAME'; refusing to write a sudoers rule." >&2; exit 1; }

if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python3" ]; then
    VENV="$VIRTUAL_ENV"
elif [ -x "$REPO/.venv/bin/python3" ]; then
    VENV="$REPO/.venv"
elif [ -x "$REPO/venv/bin/python3" ]; then
    VENV="$REPO/venv"
else
    echo "No virtualenv found (looked for \$VIRTUAL_ENV, .venv and venv in $REPO)." >&2
    exit 1
fi
PY="$VENV/bin/python-netmind"

if [ "${1:-}" = "--remove" ]; then
    rm -f "$PY"
    sudo rm -f "$SUDOERS" "$HELPER"
    echo "Removed $PY, $SUDOERS and $HELPER."
    exit 0
fi

echo "== 1/3  Raw-socket capability for ARP scanning"
base="$(readlink -f "$VENV/bin/python3")"
cp --remove-destination "$base" "$PY"
chmod 750 "$PY"
sudo setcap cap_net_raw+ep "$PY"
if ! "$PY" -c "import socket, scapy.all; socket.socket(socket.AF_PACKET, socket.SOCK_RAW).close()" 2>/dev/null; then
    rm -f "$PY"
    echo "The capability did not work on this machine (filesystem without xattr support, or a" >&2
    echo "Python build that cannot run with file capabilities). Removed $PY." >&2
    echo "ARP scanning will keep falling back to ping; nothing else was changed." >&2
    exit 1
fi
echo "   ok: $PY can open raw sockets and import scapy"

echo "== 2/3  Validated re-attach helper"
sudo install -o root -g root -m 0755 "$REPO/scripts/netmind-reconnect" "$HELPER"

echo "== 3/3  sudo rule for that helper only"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
echo "$USER_NAME ALL=(root) NOPASSWD: $HELPER" > "$tmp"
sudo visudo -cf "$tmp" >/dev/null
sudo install -o root -g root -m 0440 "$tmp" "$SUDOERS"
sudo visudo -c >/dev/null

echo "== Check"
sudo -k
if sudo -n "$HELPER" --check >/dev/null 2>&1; then
    echo "   ok: sudo runs the helper without a password"
else
    echo "   the sudo rule does not work; run: scripts/setup-permissions.sh --remove" >&2
    exit 1
fi
echo "Done. Start the app with: make run   (no sudo needed for the server)"
