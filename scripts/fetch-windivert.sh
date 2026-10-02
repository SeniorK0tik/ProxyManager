#!/usr/bin/env bash
# Downloads WinDivert (x64 DLL + signed driver), e.g. for packaging a cross-compiled build.
set -euo pipefail
VERSION="${1:-2.2.2}"
DEST="${2:-vendor/windivert}"
NAME="WinDivert-${VERSION}-A"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fsSL -o "$TMP/$NAME.zip" "https://github.com/basil00/WinDivert/releases/download/v${VERSION}/${NAME}.zip"
unzip -q "$TMP/$NAME.zip" -d "$TMP"
mkdir -p "$DEST"
cp "$TMP/$NAME/x64/WinDivert.dll" "$TMP/$NAME/x64/WinDivert64.sys" "$DEST/"
cp "$TMP/$NAME/LICENSE" "$DEST/WinDivert-LICENSE.txt" 2>/dev/null || true
sha256sum "$DEST"/WinDivert*
