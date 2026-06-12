# Installation Guide

## Prerequisites

- **Go 1.21+** — https://go.dev/dl/
- **Git** — for cloning the repository
- **GNU Make** — for building (optional, you can run `go build` directly)

### Platform-specific

| OS | Make | CGO (GUI) |
|----|------|-----------|
| **macOS** | Built-in via Xcode CLI tools | Xcode Command Line Tools (`xcode-select --install`) |
| **Linux** | `apt install build-essential` | `apt install build-essential` |
| **Windows** | `choco install make` or MSYS2 | MinGW-w64 (see below) |

## macOS

### Option 1: Homebrew (recommended for Go)

```bash
# Install Go
brew install go

# Clone and build
git clone https://github.com/babico/kryp.git
cd data-encrypter-decrypter
make build

# Install to PATH
sudo cp bin/encrypt-cli /usr/local/bin/
encrypt-cli --help
```

### Option 2: Official tarball

```bash
# Download latest Go
curl -LO https://go.dev/dl/go1.26.3.darwin-amd64.tar.gz
# For Apple Silicon:
# curl -LO https://go.dev/dl/go1.26.3.darwin-arm64.tar.gz

sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.26.3.darwin-amd64.tar.gz
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.zshrc
source ~/.zshrc

# Clone and build
git clone https://github.com/babico/kryp.git
cd data-encrypter-decrypter
make build
sudo cp bin/encrypt-cli /usr/local/bin/
```

### GUI (requires CGO)

```bash
xcode-select --install   # Install Xcode CLI tools if not present
make build-gui
sudo cp bin/encrypt-gui /usr/local/bin/
```

## Linux

### Debian / Ubuntu

```bash
# Install Go from repos
sudo apt update
sudo apt install -y golang-go git make

# Or install latest from tarball:
# curl -LO https://go.dev/dl/go1.26.3.linux-amd64.tar.gz
# sudo rm -rf /usr/local/go
# sudo tar -C /usr/local -xzf go1.26.3.linux-amd64.tar.gz
# echo 'export PATH=/usr/local/go/bin:$PATH' | sudo tee /etc/profile.d/go.sh
# source /etc/profile.d/go.sh

# Build
git clone https://github.com/babico/kryp.git
cd data-encrypter-decrypter
make build
sudo cp bin/encrypt-cli /usr/local/bin/
```

### RHEL / Fedora

```bash
# Install Go from toolset
sudo dnf install -y go-toolset git make

# Or from tarball:
# curl -LO https://go.dev/dl/go1.26.3.linux-amd64.tar.gz
# sudo rm -rf /usr/local/go
# sudo tar -C /usr/local -xzf go1.26.3.linux-amd64.tar.gz
# echo 'export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH' >> ~/.bashrc
# source ~/.bashrc

git clone https://github.com/babico/kryp.git
cd data-encrypter-decrypter
make build
sudo cp bin/encrypt-cli /usr/local/bin/
```

### Arch Linux

```bash
sudo pacman -S go git make
git clone https://github.com/babico/kryp.git
cd data-encrypter-decrypter
make build
sudo cp bin/encrypt-cli /usr/local/bin/
```

### GUI (requires CGO)

```bash
sudo apt install build-essential libgl1-mesa-dev xorg-dev  # Debian/Ubuntu
make build-gui
sudo cp bin/encrypt-gui /usr/local/bin/
```

## Windows

### Option 1: Go + Make (using MSYS2 or Chocolatey)

```powershell
# Install Go from https://go.dev/dl/ (MSI installer)
# or with winget:
winget install GoLang.Go

# Install Make
# With Chocolatey: choco install make
# With MSYS2: pacman -S make

# Clone and build
git clone https://github.com/babico/kryp.git
cd data-encrypter-decrypter
make build

# Binary at bin\encrypt-cli
# Add to PATH:
# $env:Path += ";$pwd\bin"
```

### Option 2: Go only (no Make)

```powershell
git clone https://github.com/babico/kryp.git
cd data-encrypter-decrypter
go build -trimpath -o bin\encrypt-cli.exe .\cmd\cli\

# Add to PATH:
# $env:Path += ";$pwd\bin"
```

### GUI (requires MinGW-w64)

```powershell
# Install MinGW-w64 (with Chocolatey):
choco install mingw

# Or download from https://www.mingw-w64.org/
# Ensure gcc is in PATH:
gcc --version

go build -trimpath -o bin\encrypt-gui.exe .\cmd\gui\
```

## Docker

```dockerfile
FROM golang:1.26-alpine AS build
RUN apk add --no-cache git make
WORKDIR /app
COPY . .
RUN make build

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /app/bin/encrypt-cli /usr/local/bin/
ENTRYPOINT ["encrypt-cli"]
```

Build and run:

```bash
docker build -t encrypt-cli .
docker run --rm -v $(pwd):/data encrypt-cli encrypt -s /data/original -o /data/encrypted
```

## Verify Installation

```bash
encrypt-cli --help
encrypt-cli algorithms
```

## Updating

```bash
cd data-encrypter-decrypter
git pull
make build
# Reinstall binary (Linux/macOS):
sudo cp bin/encrypt-cli /usr/local/bin/
```

## Troubleshooting

### `make: command not found`
- **macOS**: `xcode-select --install`
- **Linux (Debian/Ubuntu)**: `sudo apt install build-essential`
- **Linux (RHEL/Fedora)**: `sudo dnf install make`
- **Windows**: Install via Chocolatey (`choco install make`) or MSYS2

### CGO/GUI build fails
- Ensure GCC is installed and in PATH
- On Windows: install MinGW-w64
- On Linux: `sudo apt install build-essential libgl1-mesa-dev xorg-dev`
- On macOS: `xcode-select --install`

### `go vet` fails with locale errors on Windows
This is a known Go issue on Windows with non-English locales. Run `go vet` per-package or skip it — it does not affect functionality.

## Configuration Examples

See `docs/examples/` for working configuration templates for various scenarios:

| File | Description |
|------|-------------|
| `docs/examples/basic.yaml` | Basic XChaCha20 + Argon2id setup |
| `docs/examples/age-with-rclone.yaml` | Age asymmetric encryption with rclone cloud backup |
| `docs/examples/advanced.yaml` | AES-256-GCM + scrypt + UUID rename + rclone |

Copy an example and adjust:

```bash
cp docs/examples/basic.yaml config.yaml
# Edit config.yaml with your values
```

## Rclone Integration

After installation, set up rclone for cloud upload:

1. Install rclone: https://rclone.org/install/
2. Configure a remote: `rclone config`
3. Test connectivity: `rclone ls myremote:`
4. Encrypt and upload: `encrypt-cli encrypt -s ./data -o ./encrypted -p "pass" --upload --rclone-target "myremote:backup"`
