# Kryp — File Encryption Tool

Encrypt/decrypt files for secure storage with 19 algorithms, UUID renaming, and embedded metadata.

## Features

- **19 encryption algorithms**: XChaCha20-Poly1305, ChaCha20-Poly1305, AES-256-GCM, SecretBox, AES-256-CTR+HMAC, AEGIS-128L, AEGIS-256, AES-256-GCM-SIV, AES-256-SIV, ASCON-128, Xoodyak, Deoxys-II, Age, ML-KEM-768, ML-KEM-1024, X-Wing, HPKE, HQC-128, FrodoKEM-640-SHAKE
- **Key derivation**: Argon2id, scrypt, PBKDF2
- **Post-quantum ready**: ML-KEM (FIPS 203), X-Wing hybrid, HPKE (RFC 9180), HQC-128 (FIPS 207), FrodoKEM-640-SHAKE
- **UUID rename mode**: Encrypt files as UUIDs with manifest tracking
- **Embedded metadata**: Original filename and path in encrypted header
- **Asymmetric (Age)**: Modern file encryption with recipient/identity X25519 keys
- **GUI** (Fyne v2): Async encrypt/decrypt with resizable panes (requires CGO)
- **CLI** (Cobra): Full feature parity with 10 commands
- **Compatible mode**: Output raw ciphertext for interoperability with OpenSSL, libsodium, etc.
- **150+ unit tests + 37 E2E tests**

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

# Generate PQC keypair
kryp genkey ml-kem-768 keys/

# Inspect encrypted file header
kryp inspect test/encrypted/file.enc

# Show system info
kryp info
kryp version
```

## CLI Commands

| Command | Description |
| ------- | ----------- |
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

## Architecture

```
Binary header: [4B "ENCR"][1B version][4B bodyLen][1B hasKDF][? KDF][1B hasMeta][? meta][1B algoID][nonce][encrypted body]

Symmetric (passphrase/key):  12 ciphers (XChaCha20, AES-256-GCM, SecretBox, AES-CTR+HMAC,
                              AEGIS-128L/256, AES-GCM-SIV/SIV, ASCON-128, Xoodyak, Deoxys-II)
Asymmetric:                  Age (X25519), HPKE (RFC 9180)
Post-quantum (KEM):          ML-KEM-768/1024, X-Wing, HQC-128, FrodoKEM-640-SHAKE
KDF (passphrase→key):        Argon2id, scrypt, PBKDF2
```

## Build

```bash
make build-cli      # CLI only (bin/kryp-{os}-{arch}.exe)
make build-gui      # GUI only (requires CGO/GCC)
make build-all      # Cross-compile CLI+GUI for all platforms
make test           # Run all unit tests
make test-e2e       # Run end-to-end tests
```

### Requirements
- Go 1.26+
- `make` (GNU Make)
- GUI builds: GCC/MinGW-w64 (Windows), Xcode CLT (macOS), build-essential (Linux)

## Documentation

- [Algorithm reference](docs/ALGORITHMS.md) — full algorithm table, usage examples, aliases, raw format specs
- [Configuration examples](docs/examples/) — basic and advanced YAML configs
- [Contributing guide](CONTRIBUTING.md)

## License

DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE (WTFPL)
