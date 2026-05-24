#!/usr/bin/env bash
# CE installer — joins the global compute mesh
# Usage:  curl -sSL https://raw.githubusercontent.com/ce-net/ce/main/install.sh | bash
set -euo pipefail

REPO="ce-net/ce"
BIN="ce"
SYSTEMD_SERVICE="ce"

# ── Detect platform ───────────────────────────────────────────────────────────

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${OS}-${ARCH}" in
  linux-x86_64)   ASSET="ce-linux-amd64" ;;
  linux-aarch64)  ASSET="ce-linux-arm64" ;;
  darwin-x86_64)  ASSET="ce-macos-amd64" ;;
  darwin-arm64)   ASSET="ce-macos-arm64" ;;
  *)
    echo "ERROR: unsupported platform ${OS}-${ARCH}" >&2
    echo "Build from source: https://github.com/${REPO}" >&2
    exit 1
    ;;
esac

# ── Resolve latest release ────────────────────────────────────────────────────

echo "Fetching latest CE release..."
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | sed -E 's/.*"(v[^"]+)".*/\1/')

if [ -z "${LATEST}" ]; then
  echo "ERROR: could not determine latest release. Check https://github.com/${REPO}/releases" >&2
  exit 1
fi

URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET}"
echo "Downloading CE ${LATEST} (${ASSET})..."

# ── Download ──────────────────────────────────────────────────────────────────

TMP=$(mktemp)
curl -fsSL "${URL}" -o "${TMP}"
chmod +x "${TMP}"

# ── Install binary ────────────────────────────────────────────────────────────

if [ -w /usr/local/bin ]; then
  INSTALL_DIR="/usr/local/bin"
elif sudo -n true 2>/dev/null; then
  sudo mv "${TMP}" "/usr/local/bin/${BIN}"
  INSTALL_DIR="/usr/local/bin"
else
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "${INSTALL_DIR}"
fi

[ "${TMP}" != "${INSTALL_DIR}/${BIN}" ] && mv "${TMP}" "${INSTALL_DIR}/${BIN}"
echo "Installed: ${INSTALL_DIR}/${BIN}"

if [[ ":${PATH}:" != *":${INSTALL_DIR}:"* ]]; then
  echo "  Add ${INSTALL_DIR} to your PATH or run: export PATH=\"\$PATH:${INSTALL_DIR}\""
fi

# ── systemd service (Linux only) ─────────────────────────────────────────────

if [ "${OS}" = "linux" ] && command -v systemctl &>/dev/null && [ "$(id -u)" = "0" ]; then
  CE_BIN="${INSTALL_DIR}/${BIN}"

  cat > /etc/systemd/system/${SYSTEMD_SERVICE}.service << EOF
[Unit]
Description=CE — global compute mesh node
Documentation=https://github.com/${REPO}
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStart=${CE_BIN} start
Restart=on-failure
RestartSec=10s
# Inherit BOOTSTRAP_PEERS from the environment file if present:
EnvironmentFile=-/etc/ce/env

[Install]
WantedBy=multi-user.target
EOF

  mkdir -p /etc/ce
  [ -f /etc/ce/env ] || cat > /etc/ce/env << 'EOF'
# CE environment — uncomment and set to join an existing network
# CE_BOOTSTRAP_PEERS=/ip4/1.2.3.4/tcp/4001/p2p/<peer-id>
EOF

  systemctl daemon-reload
  systemctl enable --now ${SYSTEMD_SERVICE}.service
  echo "systemd service '${SYSTEMD_SERVICE}' enabled and started."
  echo "  Logs: journalctl -u ${SYSTEMD_SERVICE} -f"
  echo "  Stop: systemctl stop ${SYSTEMD_SERVICE}"
fi

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo "CE ${LATEST} installed."
echo ""
echo "Quick start:"
echo "  ce start                         # join the mesh (mDNS finds LAN peers)"
echo "  ce start --bootstrap <multiaddr> # connect to a specific peer"
echo "  ce status                        # check node ID, height, balance"
echo ""
echo "Source: https://github.com/${REPO}"
