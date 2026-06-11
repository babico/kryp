# encrypt-cli

A secure, cross-platform CLI tool for encrypting and decrypting files with multiple algorithms, UUID-based file renaming, optional embedded metadata, and rclone cloud upload integration.

## Features

- **6 encryption algorithms**: XChaCha20-Poly1305 (default), ChaCha20-Poly1305, AES-256-GCM, NaCl SecretBox (XSalsa20-Poly1305), AES-256-CTR+HMAC-SHA256, age (X25519+ChaCha20-Poly1305)
- **3 key derivation methods**: Argon2id (default), scrypt, PBKDF2
- Raw key file support (256-bit keys)
- UUID-based file renaming with encrypted JSON manifest database
- **Embed metadata**: Store original filename and path in the encrypted file header (optional)
- Auto-detect algorithm on decrypt via header magic bytes (`ENCR`)
- Recursive directory processing
- Rclone integration for cloud upload (sync/copy)
- Cross-platform: Windows, macOS, Linux
- Optional GUI (Fyne v2)

## Quick Install

### macOS (Homebrew)

```bash
brew install go
git clone https://github.com/babico/data-encrypter-decrypter.git
cd data-encrypter-decrypter
make build
sudo cp bin/encrypt-cli /usr/local/bin/
```

### Linux (Debian/Ubuntu)

```bash
sudo apt update && sudo apt install -y golang-go git make
git clone https://github.com/babico/data-encrypter-decrypter.git
cd data-encrypter-decrypter
make build
sudo cp bin/encrypt-cli /usr/local/bin/
```

### Windows

1. Install Go from https://go.dev/dl/
2. Open PowerShell:

```powershell
git clone https://github.com/babico/data-encrypter-decrypter.git
cd data-encrypter-decrypter
make build
```

Binary is at `bin\encrypt-cli`.

### From Source (any platform)

Requires Go 1.21+

```bash
git clone https://github.com/babico/data-encrypter-decrypter.git
cd data-encrypter-decrypter
make build
```

## Usage

### Initialize

```bash
encrypt-cli init
```

Creates `config.yaml`, `test/original/`, `test/encrypted/`, `test/decrypted/` directories.

### Encrypt Files

```bash
encrypt-cli encrypt -s test/original -o test/encrypted -p "your-passphrase"
```

With UUID rename and embedded metadata:

```bash
encrypt-cli encrypt -s test/original -o test/encrypted -p "your-passphrase" -u -m
```

With age encryption:

```bash
encrypt-cli encrypt -s test/original -o test/encrypted --algorithm age --age-recipient "age1..."
```

### Decrypt Files

```bash
encrypt-cli decrypt -s test/encrypted -o test/decrypted -p "your-passphrase"
```

Selective decrypt by UUID or filename:

```bash
encrypt-cli decrypt -s test/encrypted -o test/decrypted -p "your-passphrase" --select "file.txt,abc12345"
```

Recreate directory structure from embedded metadata:

```bash
encrypt-cli decrypt -s test/encrypted -o test/decrypted -p "your-passphrase" --keep-path
```

### List Encrypted Files

```bash
encrypt-cli list test/encrypted
```

### List Algorithms

```bash
encrypt-cli algorithms
```

### Generate Keys

```bash
encrypt-cli genkey xchacha20-poly1305 mykey.bin
encrypt-cli genkey age age-recipient.txt   # Generates age key pair
```

## Rclone Integration

Automatically upload encrypted files to any cloud storage supported by [rclone](https://rclone.org/).

### Setup

1. Install rclone: `curl https://rclone.org/install.sh | sudo bash`
2. Configure a remote: `rclone config`
3. Test: `rclone ls myremote:`

### Usage

**Encrypt and upload in one step:**

```bash
encrypt-cli encrypt -s ./docs -o ./encrypted -p "secret" --upload --rclone-target "mydropbox:backups"
```

**Or separate (upload after encryption):**

```bash
encrypt-cli encrypt -s ./docs -o ./encrypted -p "secret"
encrypt-cli encrypt -s ./encrypted -o ./encrypted --rclone-target "mydropbox:backups" --upload
```

### Rclone Modes

| Mode | Flag | Behavior |
|------|------|----------|
| **sync** (default, incremental) | `incremental: true` | `rclone sync` — mirrors source to dest, deletes extraneous files at destination |
| **copy** | `incremental: false` | `rclone copy` — copies all files, leaves dest untouched |

### Config via YAML

```yaml
storage:
  type: rclone
  rclone:
    remote_path: "mydropbox:backups/encrypted"
    binary: /usr/local/bin/rclone
    incremental: true
    args: -v --progress --checksum
```

### Checking Rclone Availability

```bash
encrypt-cli encrypt -s ./docs -o ./encrypted -p "secret" --rclone-target "mydropbox:backups"
# If rclone is missing, you'll see: "rclone not found in PATH"
```

## Examples

Complete working configuration examples for various scenarios are in `docs/examples/`:

| File | Scenario |
|------|----------|
| `docs/examples/basic.yaml` | XChaCha20 + Argon2id, local storage |
| `docs/examples/age-with-rclone.yaml` | Age encryption + rclone cloud backup |
| `docs/examples/advanced.yaml` | AES-256-GCM + scrypt + UUID rename + rclone |

## Algorithms

| ID | Algorithm | Key Size | Nonce Size | Auth |
|----|-----------|----------|------------|------|
| 1 | XChaCha20-Poly1305 | 32B | 24B | AEAD |
| 2 | ChaCha20-Poly1305 | 32B | 12B | AEAD |
| 3 | AES-256-GCM | 32B | 12B | AEAD |
| 4 | NaCl SecretBox (XSalsa20-Poly1305) | 32B | 24B | AEAD |
| 5 | AES-256-CTR+HMAC-SHA256 | 32B | 16B | Encrypt-then-MAC |
| 6 | age (X25519+ChaCha20-Poly1305) | — | — | Asymmetric |

## Configuration

Configuration file (`config.yaml` or `config.yml`) is loaded automatically from the current directory or `~/.encrypt-cli.yaml`. See `config.yaml.example` and `docs/examples/` for templates.

```yaml
encryption:
  algorithm: xchacha20-poly1305      # Algorithm: xchacha20-poly1305, chacha20-poly1305, aes-256-gcm, secretbox, aes-256-ctr-hmac, age
  key_file: ""                        # Path to raw key file (256-bit)
  kdf_method: argon2id               # Key derivation: argon2id, scrypt, pbkdf2
  passphrase: ""                      # Encryption passphrase (overrides key_file if set)
  uuid_rename: false                  # Rename files to UUID on encrypt
  embed_metadata: false               # Embed original name/path in header

storage:
  type: local                         # Storage type: local, rclone
  rclone:
    remote_path: ""                   # Rclone remote:path (e.g. mydropbox:backup)
    binary: rclone                    # Path to rclone binary
    incremental: true                 # Use rclone sync (true) or copy (false)
    args: -v --progress               # Extra rclone arguments

database:
  encrypt: true                       # Encrypt the manifest JSON
  format: json                        # Manifest format (json only)

directories:
  source: test/original               # Default source (encrypt input)
  output: test/encrypted              # Default output (encrypted files)
  decrypted: test/decrypted           # Default decrypted output
```

## CLI Flags Reference

| Flag | Short | Command | Description |
|------|-------|---------|-------------|
| `--algorithm` | `-a` | encrypt | Encryption algorithm (default: `xchacha20-poly1305`) |
| `--passphrase` | `-p` | encrypt, decrypt | Encryption passphrase |
| `--key-file` | `-k` | encrypt, decrypt | Path to key file (256-bit binary key) |
| `--kdf` | | encrypt | Key derivation method (default: `argon2id`) |
| `--uuid-rename` | `-u` | encrypt | Rename files to UUID |
| `--embed-metadata` | `-m` | encrypt | Embed original filename/path in header |
| `--age-recipient` | | encrypt | Age recipient public key |
| `--keep-path` | | decrypt | Recreate directory structure from metadata |
| `--select` | | decrypt | UUIDs or filenames to decrypt (comma-separated) |
| `--upload` | | encrypt | Upload to cloud after encryption |
| `--rclone-target` | `-r` | encrypt | Rclone remote:path target |
| `--source` | `-s` | encrypt, decrypt | Source directory |
| `--output` | `-o` | encrypt, decrypt | Output directory |
| `--config` | `-c` | all | Config file path |

## Development

```bash
make build           # Build CLI for current platform
make build-all       # Cross-compile (Linux/Windows/macOS)
make build-gui       # Build GUI (requires CGO/GCC)
make test            # Run unit tests
make test-e2e        # Run end-to-end tests
make test-all        # Run all tests (unit + e2e)
make test-race       # Tests with race detector
make test-coverage   # Coverage report
make bench           # Run benchmarks
make clean           # Remove build artifacts
make lint            # Run linters (go vet + staticcheck)
make fmt             # Format code
make deps            # Tidy and verify dependencies
```

## File Format

Encrypted files use a custom binary header:

```
[4B magic "ENCR"] [1B version] [4B body length] [? body]
```

Body layout:
- `[1B hasKDF]` — KDF presence flag
- `[? KDF data]` — salt, params (if hasKDF)
- `[1B hasMetadata]` — metadata presence flag
- `[? metadata]` — flags + length-prefixed name/path (if hasMetadata)
- `[1B algoID]` — algorithm identifier
- `[? nonce]` — algorithm-specific nonce

Followed by the ciphertext.

## License

MIT
