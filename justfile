set windows-shell := ["pwsh", "-NoLogo", "-Command"]

version := `git describe --tags --always --dirty 2>/dev/null || echo dev`
commit := `git rev-parse --short HEAD 2>/dev/null || echo none`
ldflags := "-s -w -X github.com/wexelsdev/beryllium/internal/version.Version=" + version + " -X github.com/wexelsdev/beryllium/internal/version.Commit=" + commit

default:
    @just --list

# Generate code from proto (phase 1)
gen:
    buf generate

# Build daemon and CLI into ./bin
build:
    go build -ldflags "{{ldflags}}" -o bin/ ./cmd/...

test:
    go test -race ./...

lint:
    golangci-lint run
    gofmt -l . | (! grep .)

fmt:
    gofmt -w .

run-daemon *args:
    go run ./cmd/berylliumd {{args}}

# Download pinned core binaries (phase 5)
fetch-cores:
    @echo "not implemented yet (ROADMAP 5.2)"

# GUI dev mode (phase 9)
gui-dev:
    @echo "not implemented yet (ROADMAP 9.1)"
