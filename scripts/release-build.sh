#!/usr/bin/env bash
# Builds a release archive for one platform into dist/ (used by the release
# workflow; works locally too). Cores must be fetched first:
#   go -C tools run ./fetchcores -platform <goos>-<goarch>
# Env: GOOS, GOARCH (default: this machine), VERSION (default: git describe).
set -euo pipefail

goos=${GOOS:-$(go env GOOS)}
goarch=${GOARCH:-$(go env GOARCH)}
version=${VERSION:-$(git describe --tags --always --dirty)}
commit=$(git rev-parse --short HEAD)
date=$(date -u +%Y-%m-%dT%H:%M:%SZ)

name="beryllium_${version#v}_${goos}_${goarch}"
out="dist/$name"
rm -rf "$out"
mkdir -p "$out/cores"

# macOS needs cgo for IOKit sleep/wake notifications; Linux and Windows
# build without it.
export GOOS=$goos GOARCH=$goarch CGO_ENABLED=0
if [ "$goos" = darwin ]; then
	export CGO_ENABLED=1
	[ "$goarch" = amd64 ] && export CC="clang -arch x86_64"
	[ "$goarch" = arm64 ] && export CC="clang -arch arm64"
fi
pkg=github.com/vvaeli/beryllium/internal/version
go build -trimpath -ldflags "-s -w -X $pkg.Version=$version -X $pkg.Commit=$commit -X $pkg.Date=$date" \
	-o "$out/" ./cmd/berylliumd ./cmd/beryl

cores="cores/bin/$goos-$goarch"
[ -d "$cores" ] || { echo "no cores in $cores; run: go -C tools run ./fetchcores -platform $goos-$goarch" >&2; exit 1; }
cp "$cores"/* "$out/cores/"
cp LICENSE README.md "$out/"
cp -R packaging "$out/packaging"

exe="" cli=./beryl
[ "$goos" = windows ] && exe=.exe cli=beryl.exe
case "$goos" in
windows) install="berylliumd$exe install   (in an Administrator terminal)
berylliumd$exe start" ;;
*) install="sudo ./berylliumd install
sudo ./berylliumd start" ;;
esac
cat >"$out/INSTALL.txt" <<TXT
Beryllium $version ($goos/$goarch)

Unpack to a permanent location (the service runs the daemon from here),
then install and start the service:

$install

Then use the CLI as your user: $cli --help
TXT
if [ "$goos" = darwin ]; then
	cat >>"$out/INSTALL.txt" <<'TXT'

The binaries are not notarized. If macOS blocks them, remove the
quarantine flag first: xattr -dr com.apple.quarantine .
TXT
fi

cd dist
if [ "$goos" = windows ]; then
	rm -f "$name.zip"
	zip -qr "$name.zip" "$name"
	echo "dist/$name.zip"
else
	tar -czf "$name.tar.gz" "$name"
	echo "dist/$name.tar.gz"
fi
