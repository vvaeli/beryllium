set windows-shell := ["pwsh", "-NoLogo", "-Command"]

version := `git describe --tags --always --dirty 2>/dev/null || echo dev`
commit := `git rev-parse --short HEAD 2>/dev/null || echo none`
buf := "go tool -modfile=tools/go.mod buf"
# Same version as CI; runs via go run, no global install needed.
golangci := "go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0"
ldflags := "-s -w -X github.com/vvaeli/beryllium/internal/version.Version=" + version + " -X github.com/vvaeli/beryllium/internal/version.Commit=" + commit

default:
    @just --list

# Generate Go code from proto into gen/go
gen:
    {{buf}} format -w
    {{buf}} generate

# Build daemon and CLI into ./bin
build:
    go build -ldflags "{{ldflags}}" -o bin/ ./cmd/...

test:
    go test -race ./...

lint:
    {{buf}} lint
    {{golangci}} run
    gofmt -l . | (! grep .)

fmt:
    gofmt -w .
    {{buf}} format -w

# Check proto changes for breaking changes against main
breaking:
    {{buf}} breaking --against '.git#branch=main'

platform := `go env GOOS` + "-" + `go env GOARCH`

# Run the daemon unprivileged with state in ./.dev (no TUN/system changes)
run-daemon *args:
    go run ./cmd/berylliumd -foreground -config-dir .dev/state -log-dir .dev/logs -socket .dev/d.sock -cores-dir cores/bin/{{platform}} {{args}}

# Download pinned cores (cores/versions.json) into cores/bin/<os>-<arch>; pass "-platform all" for every OS
fetch-cores *args:
    go -C tools run ./fetchcores {{args}}

# Tests in a Linux container like CI (unprivileged, no ICMP); needs Docker (colima on macOS)
test-linux: (fetch-linux-cores)
    docker run --rm --sysctl net.ipv4.ping_group_range="1 0" --user 1000:1000 \
        -e HOME=/tmp -e GOCACHE=/tmp/gocache -v beryllium-gomod:/go/pkg/mod \
        -v "$PWD":/src -w /src golang:1.27 go test -race ./...

# TUN end-to-end in a Linux container as root (scripts/tun-e2e.sh)
test-linux-tun: (fetch-linux-cores)
    mkdir -p .dev/linux
    GOOS=linux GOARCH={{linux_arch}} go build -o .dev/linux/ ./cmd/berylliumd ./cmd/beryl
    docker run --rm --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv6.conf.all.disable_ipv6=0 \
        -v "$PWD/.dev/linux":/b -v "$PWD/cores/bin/linux-{{linux_arch}}":/c:ro -v "$PWD/scripts":/s:ro golang:1.27 \
        sh -c 'apt-get -qq update && apt-get -qq install -y iproute2 >/dev/null && /s/tun-e2e.sh'

linux_arch := `go env GOARCH`

# Download cores for Linux on this CPU architecture (for the container tests)
fetch-linux-cores:
    go -C tools run ./fetchcores -platform linux-{{linux_arch}}

# Update cores/versions.json to the latest releases
bump-cores:
    go -C tools run ./fetchcores -bump

# GUI dev mode (phase 9)
gui-dev:
    @echo "not implemented yet (ROADMAP 9.1)"
