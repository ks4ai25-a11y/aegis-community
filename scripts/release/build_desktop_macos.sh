#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
set -euo pipefail

if [[ $# != 1 || $(uname -s) != Darwin ]]; then
    echo "Usage on macOS: $0 OUTPUT_BINARY" >&2
    exit 2
fi

root="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$(dirname "$1")"
output="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
if [[ -d "$output" ]]; then
    echo "The output must be a file path." >&2
    exit 2
fi
work="$(mktemp -d "$(dirname "$output")/.aegis-macos-build.XXXXXX")"
trap 'rm -rf "$work"' EXIT

CC="$(xcrun --sdk macosx --find clang)"
SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
export CC SDKROOT
export CGO_ENABLED=1 GOOS=darwin GOFLAGS=-mod=readonly
export MACOSX_DEPLOYMENT_TARGET=14.0 GOAMD64=v1 GOARM64=v8.0

cd "$root/controller"
for arch in amd64 arm64; do
    GOARCH="$arch" go build -trimpath -buildvcs=false \
        '-ldflags=-buildid= -linkmode=external -extldflags=-Wl,-no_uuid' \
        -o "$work/aegis-mcp-$arch" ./cmd/aegis-mcp
done

/usr/bin/lipo -create "$work/aegis-mcp-amd64" "$work/aegis-mcp-arm64" -output "$work/aegis-mcp"
/usr/bin/lipo "$work/aegis-mcp" -verify_arch x86_64 arm64
# The reproducible preview signature allows local execution on both architectures.
/usr/bin/codesign --force --sign - --timestamp=none --identifier ai.kynthia.aegis.mcp "$work/aegis-mcp"
/usr/bin/codesign --verify --strict --all-architectures "$work/aegis-mcp"
mv -f "$work/aegis-mcp" "$output"
