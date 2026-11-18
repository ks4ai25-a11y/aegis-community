#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
set -euo pipefail

if [[ $# != 1 || $(uname -s) != Darwin ]]; then
    echo "Usage on macOS: $0 NEW_OUTPUT_DIRECTORY" >&2
    exit 2
fi
: "${AEGIS_DEVELOPER_ID_APPLICATION:?Set the exact Developer ID Application identity name}"
: "${AEGIS_NOTARY_PROFILE:?Set the name of a notarytool Keychain profile}"
identity="$AEGIS_DEVELOPER_ID_APPLICATION"
if [[ "$identity" != 'Developer ID Application: '* ]]; then
    echo "A Developer ID Application identity is required." >&2
    exit 2
fi

root="$(cd "$(dirname "$0")/../.." && pwd)"
output="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
if [[ -e "$output" || -L "$output" ]]; then
    echo "Choose a new output directory." >&2
    exit 2
fi
if [[ -n "$(git -C "$root" status --porcelain --untracked-files=normal)" ]]; then
    echo "Build release packages from a clean source checkout." >&2
    exit 2
fi
commit="$(git -C "$root" rev-parse HEAD)"
work="$(mktemp -d "$(dirname "$output")/.aegis-macos-release.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir "$work/volume" "$work/deliverables"
binary="$work/volume/aegis-mcp-keychain"
dmg="$work/deliverables/aegis-mcp-macos-universal.dmg"

bash "$root/scripts/release/build_desktop_macos.sh" "$binary"
preview_hash="$(LC_ALL=C shasum -a 256 "$binary" | cut -d ' ' -f 1)"
/usr/bin/codesign --force --sign "$identity" --timestamp --options runtime \
    --identifier ai.kynthia.aegis.mcp "$binary"
/usr/bin/codesign --verify --strict --all-architectures "$binary"
for arch in arm64 x86_64; do
    /usr/bin/codesign --display --verbose=4 --arch "$arch" "$binary" 2>&1 |
        /usr/bin/grep -Fx "Authority=$identity" >/dev/null
done

cp "$root/LICENSE" "$root/NOTICE" "$work/volume/"
(
    cd "$work/volume"
    LC_ALL=C shasum -a 256 aegis-mcp-keychain > SHA256SUMS
)
{
    printf 'Aegis Desktop MCP bridge\n\nPublisher: %s\nSource commit: %s\n' "$identity" "$commit"
    printf '%s\n' 'SHA256SUMS records the signed executable checksum.'
    printf 'Setup guide: https://github.com/ks4ai25-a11y/aegis-community/blob/%s/docs/operators/assistant-connections.md\n' "$commit"
} > "$work/volume/Read Me.txt"

hdiutil create -srcfolder "$work/volume" -volname "Aegis Desktop Bridge" -format UDZO "$dmg"
/usr/bin/codesign --sign "$identity" --timestamp "$dmg"
/usr/bin/codesign --verify --strict "$dmg"
if [[ "$(git -C "$root" rev-parse HEAD)" != "$commit" ]] ||
    [[ -n "$(git -C "$root" status --porcelain --untracked-files=normal)" ]]; then
    echo "The source checkout changed during the release build." >&2
    exit 2
fi
receipt="$work/deliverables/notarization.json"
submit_status=0
xcrun notarytool submit "$dmg" --keychain-profile "$AEGIS_NOTARY_PROFILE" --wait \
    --timeout 30m --output-format json > "$receipt" || submit_status=$?
python3 - "$receipt" "$submit_status" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as record:
        result = json.load(record)
except (OSError, ValueError):
    sys.exit("Apple notarization returned no usable receipt.")
if sys.argv[2] != "0" or result.get("status") != "Accepted" or not result.get("id"):
    sys.exit(f"Apple notarization failed: {result.get('status')} (submission {result.get('id')})")
PY
xcrun stapler staple "$dmg"
xcrun stapler validate "$dmg"
hdiutil verify "$dmg"
/usr/bin/codesign --verify --strict "$dmg"
/usr/sbin/spctl --assess --type open --context context:primary-signature --verbose "$dmg"
(
    cd "$work/deliverables"
    printf 'source_commit=%s\npreview_sha256=%s\npublisher=%s\ngo=%s\nmacos_sdk=%s\n' \
        "$commit" "$preview_hash" "$identity" "$(go version)" "$(xcrun --sdk macosx --show-sdk-version)" > BUILD-INFO
    LC_ALL=C shasum -a 256 aegis-mcp-macos-universal.dmg notarization.json BUILD-INFO > SHA256SUMS
)
mv "$work/deliverables" "$output"
