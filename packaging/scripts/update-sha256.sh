#!/usr/bin/env bash
# Update SHA256 placeholders in all packaging files after a new GitHub release.
# Usage: ./packaging/scripts/update-sha256.sh <version>
# Example: ./packaging/scripts/update-sha256.sh 0.1.0
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <version>" >&2
  exit 1
fi

VERSION="$1"
REPO="ce-net/ce"
SUMS_URL="https://github.com/${REPO}/releases/download/v${VERSION}/sha256sums.txt"

echo "Fetching sha256sums.txt for v${VERSION}..."
SUMS=$(curl -fsSL "${SUMS_URL}")

get_sha() {
  echo "${SUMS}" | grep "$1" | awk '{print $1}'
}

SHA_LINUX_AMD64=$(get_sha "ce-linux-amd64.tar.gz")
SHA_LINUX_ARM64=$(get_sha "ce-linux-arm64.tar.gz")
SHA_MACOS_AMD64=$(get_sha "ce-macos-amd64.tar.gz")
SHA_MACOS_ARM64=$(get_sha "ce-macos-arm64.tar.gz")
SHA_WINDOWS=$(get_sha "ce-windows-amd64.zip")

echo "linux-amd64:   ${SHA_LINUX_AMD64}"
echo "linux-arm64:   ${SHA_LINUX_ARM64}"
echo "macos-amd64:   ${SHA_MACOS_AMD64}"
echo "macos-arm64:   ${SHA_MACOS_ARM64}"
echo "windows-amd64: ${SHA_WINDOWS}"

# ── Homebrew formula ──────────────────────────────────────────────────────────

update_formula() {
  local FORMULA="$1"
  sed -i.bak \
    -e "s|version \".*\"|version \"${VERSION}\"|" \
    -e "s|PLACEHOLDER_MACOS_ARM64|${SHA_MACOS_ARM64}|" \
    -e "s|PLACEHOLDER_MACOS_AMD64|${SHA_MACOS_AMD64}|" \
    -e "s|PLACEHOLDER_LINUX_ARM64|${SHA_LINUX_ARM64}|" \
    -e "s|PLACEHOLDER_LINUX_AMD64|${SHA_LINUX_AMD64}|" \
    "${FORMULA}"
  rm -f "${FORMULA}.bak"
  echo "Updated ${FORMULA}"
}

update_formula "Formula/ce.rb"

# Also update the homebrew-ce tap repo if it's checked out alongside this repo
TAP_FORMULA="$(dirname "$(pwd)")/homebrew-ce/Formula/ce.rb"
if [ -f "${TAP_FORMULA}" ]; then
  update_formula "${TAP_FORMULA}"
  echo "  (also synced homebrew-ce tap)"
fi

# ── Scoop manifest ────────────────────────────────────────────────────────────

SCOOP="packaging/scoop/ce.json"
python3 -c "
import json, sys
with open('${SCOOP}') as f:
    m = json.load(f)
m['version'] = '${VERSION}'
m['architecture']['64bit']['url'] = m['architecture']['64bit']['url'].rsplit('/', 2)[0] + '/v${VERSION}/ce-windows-amd64.zip'
m['architecture']['64bit']['hash'] = '${SHA_WINDOWS}'
with open('${SCOOP}', 'w') as f:
    json.dump(m, f, indent=4)
    f.write('\n')
"
echo "Updated ${SCOOP}"

# Also update the scoop-ce bucket repo if it's checked out alongside this repo
BUCKET_JSON="$(dirname "$(pwd)")/scoop-ce/bucket/ce.json"
if [ -f "${BUCKET_JSON}" ]; then
  cp "${SCOOP}" "${BUCKET_JSON}"
  echo "  (also synced scoop-ce bucket)"
fi

# ── Chocolatey ───────────────────────────────────────────────────────────────

CHOCO_NUSPEC="packaging/choco/ce.nuspec"
CHOCO_INSTALL="packaging/choco/tools/chocolateyInstall.ps1"

sed -i.bak "s|<version>.*</version>|<version>${VERSION}</version>|" "${CHOCO_NUSPEC}"
sed -i.bak "s|<releaseNotes>.*</releaseNotes>|<releaseNotes>https://github.com/${REPO}/releases/tag/v${VERSION}</releaseNotes>|" "${CHOCO_NUSPEC}"
rm -f "${CHOCO_NUSPEC}.bak"

sed -i.bak \
  -e "s|/download/v[^/]*/ce-windows|/download/v${VERSION}/ce-windows|" \
  -e "s|checksum64     = '.*'|checksum64     = '${SHA_WINDOWS}'|" \
  "${CHOCO_INSTALL}"
rm -f "${CHOCO_INSTALL}.bak"
echo "Updated ${CHOCO_NUSPEC} and ${CHOCO_INSTALL}"

# ── AUR PKGBUILD ─────────────────────────────────────────────────────────────

PKGBUILD="packaging/aur/PKGBUILD"
sed -i.bak \
  -e "s|^pkgver=.*|pkgver=${VERSION}|" \
  -e "s|sha256sums_x86_64=('.*')|sha256sums_x86_64=('${SHA_LINUX_AMD64}')|" \
  -e "s|sha256sums_aarch64=('.*')|sha256sums_aarch64=('${SHA_LINUX_ARM64}')|" \
  "${PKGBUILD}"
rm -f "${PKGBUILD}.bak"
echo "Updated ${PKGBUILD}"

echo ""
echo "All packaging files updated for v${VERSION}."
echo ""
echo "Next steps:"
echo "  1. cd /path/to/ce-net/ce    && git add -A && git commit -m 'chore: bump packaging to v${VERSION}' && git push"
echo "  2. cd /path/to/homebrew-ce  && git add -A && git commit -m 'chore: bump formula to v${VERSION}' && git push"
echo "  3. cd /path/to/scoop-ce     && git add -A && git commit -m 'chore: bump manifest to v${VERSION}' && git push"
