APP_NAME := encrypt-cli
GUI_NAME := encrypt-gui
NULL := $(if $(findstring Windows,$(OS)),nul,/dev/null)
VERSION := $(shell git describe --tags --always 2>$(NULL) || echo dev)
LDFLAGS := -ldflags="-X main.version=$(VERSION)"
GO := go
GOFLAGS := -trimpath

.PHONY: all build build-cli build-cli-all build-all
.PHONY: build-cli-linux build-cli-windows build-cli-darwin build-cli-darwin-arm64
.PHONY: build-gui build-gui-linux build-gui-windows build-gui-darwin build-gui-all
.PHONY: test test-unit test-e2e test-all test-short test-race test-coverage bench
.PHONY: e2e-quick e2e-full
.PHONY: clean lint fmt deps init run help

## ======== Build ========

all: build test

build: build-cli

build-cli:
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(APP_NAME)$(SUFFIX) ./cmd/cli/

build-gui:
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(GUI_NAME)$(SUFFIX) ./cmd/gui/

build-cli-all: build-cli-linux build-cli-windows build-cli-darwin build-cli-darwin-arm64

build-all: build-cli-all build-gui-all

build-gui-all: build-gui-linux build-gui-windows build-gui-darwin

# Cross-compile helpers — use "set VAR=val &&" on Windows cmd.exe, "VAR=val" on Unix
ifneq ($(OS),Windows_NT)

build-cli-linux:
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(APP_NAME)-linux-amd64 ./cmd/cli/
build-cli-windows:
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(APP_NAME)-windows-amd64.exe ./cmd/cli/
build-cli-darwin:
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(APP_NAME)-darwin-amd64 ./cmd/cli/
build-cli-darwin-arm64:
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(APP_NAME)-darwin-arm64 ./cmd/cli/

build-gui-linux:
	-GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(GUI_NAME)-linux-amd64 ./cmd/gui/
build-gui-windows:
	-GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(GUI_NAME)-windows-amd64.exe ./cmd/gui/
build-gui-darwin:
	-GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(GUI_NAME)-darwin-amd64 ./cmd/gui/

else

build-cli-linux:
	set GOOS=linux&& set GOARCH=amd64&& $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(APP_NAME)-linux-amd64 ./cmd/cli/
build-cli-windows:
	set GOOS=windows&& set GOARCH=amd64&& $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(APP_NAME)-windows-amd64.exe ./cmd/cli/
build-cli-darwin:
	set GOOS=darwin&& set GOARCH=amd64&& $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(APP_NAME)-darwin-amd64 ./cmd/cli/
build-cli-darwin-arm64:
	set GOOS=darwin&& set GOARCH=arm64&& $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(APP_NAME)-darwin-arm64 ./cmd/cli/

build-gui-linux:
	-set GOOS=linux&& set GOARCH=amd64&& $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(GUI_NAME)-linux-amd64 ./cmd/gui/
build-gui-windows:
	set GOOS=windows&& set GOARCH=amd64&& $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(GUI_NAME)-windows-amd64.exe ./cmd/gui/
build-gui-darwin:
	-set GOOS=darwin&& set GOARCH=amd64&& $(GO) build $(GOFLAGS) $(LDFLAGS) -o bin/$(GUI_NAME)-darwin-amd64 ./cmd/gui/

endif

run:
	$(GO) run ./cmd/cli/

## ======== Test ========

test: test-unit

test-unit:
	-$(GO) vet ./...
	$(GO) test -v -count=1 -timeout 120s ./internal/...

test-e2e:
	$(GO) test -v -count=1 -timeout 300s ./test/...

test-all: test-unit test-e2e

test-short:
	$(GO) test -short -count=1 ./internal/...

test-race:
	$(GO) test -race -count=1 ./internal/...

test-coverage:
	$(GO) test -coverprofile=coverage.out -count=1 ./internal/...
	$(GO) tool cover -html=coverage.out -o coverage.html

bench:
	$(GO) test -bench=. -benchmem ./internal/...

## ======== E2E ========

e2e-quick:
	$(GO) test -v -count=1 -timeout 300s -run 'TestE2E_XChaCha20|TestE2E_AESGCM|TestE2E_RawKey|TestE2E_WrongPassphrase' ./test/...

e2e-full:
	$(GO) test -v -count=1 -timeout 600s ./test/...

## ======== Quality ========

lint:
	$(GO) vet ./...
	staticcheck ./... 2>/dev/null || echo "staticcheck not installed, skipping"

fmt:
	$(GO) fmt ./...

## ======== Dependencies ========

deps:
	$(GO) mod tidy
	$(GO) mod verify

## ======== Clean ========

clean:
	$(GO) clean ./...
	rm -rf bin/ 2>/dev/null || (if exist bin\ rmdir /s /q bin)
	rm -f $(APP_NAME).exe $(APP_NAME) 2>/dev/null || (if exist $(APP_NAME).exe del /q $(APP_NAME).exe)
	rm -f coverage.out coverage.html 2>/dev/null || (if exist coverage.out del /q coverage.out) & (if exist coverage.html del /q coverage.html)
	rm -f test/encrypted/*.enc test/decrypted/* 2>/dev/null || (if exist test\encrypted\*.enc del /q test\encrypted\*.enc) & (if exist test\decrypted\* del /q test\decrypted\*)

## ======== Init ========

init:
	$(GO) run ./cmd/cli/ init

## ======== Help ========

help:
	@echo "=== $(APP_NAME) Makefile ==="
	@echo ""
	@echo "Build:"
	@echo "  make build           - Build CLI for current platform"
	@echo "  make build-cli       - Build CLI for current platform"
	@echo "  make build-cli-all   - Cross-compile CLI for Linux/Windows/macOS"
	@echo "  make build-gui       - Build GUI for current platform (requires CGO)"
	@echo "  make build-gui-all   - Cross-compile GUI for all platforms"
	@echo "  make build-all       - Cross-compile CLI + GUI for all platforms"
	@echo "  make run             - Run CLI directly without building"
	@echo ""
	@echo "Test:"
	@echo "  make test            - Run unit tests"
	@echo "  make test-e2e        - Run end-to-end tests"
	@echo "  make test-all        - Run all tests (unit + e2e)"
	@echo "  make test-short      - Run unit tests in short mode"
	@echo "  make test-race       - Run tests with race detector"
	@echo "  make test-coverage   - Generate HTML coverage report"
	@echo "  make bench           - Run benchmarks"
	@echo ""
	@echo "E2E Scenarios:"
	@echo "  - All 6 algorithms: XChaCha20, ChaCha20, AES-GCM, SecretBox, AES-CTR+HMAC, age"
	@echo "  - All 3 KDFs: Argon2id, scrypt, PBKDF2"
	@echo "  - Raw key encryption/decryption"
	@echo "  - UUID rename mode"
	@echo "  - Wrong passphrase rejection"
	@echo "  - Large file (5MB)"
	@echo "  - Empty directory"
	@echo "  - Auto-detection via header magic bytes"
	@echo ""
	@echo "  make e2e-quick        - Run subset of E2E tests"
	@echo "  make e2e-full         - Run all E2E tests (longer timeout)"
	@echo ""
	@echo "Quality:"
	@echo "  make lint             - Run go vet + staticcheck"
	@echo "  make fmt              - Format all Go code"
	@echo "  make deps             - Tidy and verify dependencies"
	@echo ""
	@echo "Other:"
	@echo "  make clean            - Remove build artifacts and test output"
	@echo "  make init             - Create default config and test directories"
