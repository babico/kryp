# Kryp — File Encryption Tool

Encrypt/decrypt files for secure storage with multiple algorithms and UUID renaming.

## Features

- **11 encryption algorithms**: XChaCha20-Poly1305, ChaCha20-Poly1305, AES-256-GCM, SecretBox, AES-256-CTR+HMAC, Age, ML-KEM-768, ML-KEM-1024, X-Wing, HPKE, ASCON-128
- **Key derivation**: Argon2id, scrypt, PBKDF2
- **Post-quantum ready**: ML-KEM (FIPS 203), X-Wing hybrid, HPKE (RFC 9180)
- **UUID rename**: Encrypt files as UUIDs with manifest tracking
- **Embedded metadata**: Original filename and path in encrypted header
- **GUI** (Fyne v2): Async encrypt/decrypt with resizable panes
- **CLI** (Cobra): Full feature parity with 10 commands

## Quick Start

```bash
# Initialize project
kryp init

# Encrypt
kryp encrypt --source test/original --output test/encrypted

# Decrypt
kryp decrypt --source test/encrypted --output test/decrypted

# List algorithms
kryp algorithms

# Generate a key
kryp genkey xchacha20-poly1305 keys/mykey.bin

# Inspect encrypted file header
kryp inspect test/encrypted/file.enc

# Show version
kryp version
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `encrypt` | Encrypt files from source to output directory |
| `decrypt` | Decrypt files from encrypted to output directory |
| `list` | List encrypted files from manifest |
| `algorithms` | List supported encryption algorithms |
| `genkey` | Generate random key or keypair |
| `init` | Initialize config and test directories |
| `version` | Show version information |
| `inspect` | Inspect encrypted file header |
| `hash` | Compute file hash (SHA256/SHA512) |
| `info` | Show system and crypto information |

## Build

```bash
make build-cli      # CLI only (bin/kryp-windows-amd64.exe)
make build-gui      # GUI only (requires CGO)
make build-all      # Cross-compile all platforms
```

## License

DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE (WTFPL)
