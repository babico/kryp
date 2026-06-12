# AGENTS.md — AI Agent Guide

## Project Overview

`kryp` is a Go CLI+GUI tool for encrypting/decrypting files with multiple algorithms, UUID rename, and embedded metadata. Module: `github.com/babico/kryp`.

## Key Files

| File | Purpose |
| ---- | ------- |
| `internal/crypto/header.go` | Binary header with magic bytes `ENCR`, metadata support |
| `internal/crypto/registry.go` | Algorithm registry, `EncryptFile`, `DecryptFile`, `EncryptFileBytes`, `DecryptFileBytes` |
| `internal/crypto/types.go` | `AlgorithmID`, `KDFMethod` enums, `Encryptor` interface, `ParseAlgorithm`/`ParseKDF` |
| `internal/crypto/keyderivation.go` | `DeriveKey` (Argon2id/scrypt/PBKDF2) |
| `internal/crypto/age.go` | Age encryptor implementation |
| `internal/crypto/mlkem768.go` | ML-KEM-768 (FIPS 203) post-quantum encryptor |
| `internal/crypto/mlkem1024.go` | ML-KEM-1024 (FIPS 203) higher-security post-quantum encryptor |
| `internal/crypto/xwing.go` | Hybrid X-Wing (X25519+ML-KEM-768) defense-in-depth encryptor |
| `internal/crypto/hpke.go` | HPKE (RFC 9180) encryptor |
| `internal/crypto/ascon.go` | ASCON-128 (NIST LW) encryptor |
| `internal/crypto/symmetric/` | Symmetric ciphers (XChaCha20, ChaCha20, AES-GCM, SecretBox, AES-CTR+HMAC) |
| `cmd/cli/main.go` | Cobra CLI with 10 commands: encrypt, decrypt, list, algorithms, genkey, init, version, inspect, hash, info |
| `cmd/gui/main.go` | Fyne v2 GUI with async encrypt/decrypt, collapsible sections, key gen modal |
| `internal/db/manifest.go` | UUID manifest database |
| `internal/store/rclone.go` | Rclone uploader |
| `internal/config/config.go` | YAML config struct, `ApplyEnvOverrides` for `ENCRYPT_CLI_PASSPHRASE`/`ENCRYPT_CLI_KEY_FILE` |
| `docs/examples/*.yaml` | Configuration examples (basic, age+rclone, advanced) |
| `test/e2e_test.go` | End-to-end tests |

## Architecture Notes

- **Header format**: `[4B "ENCR"][1B version][4B bodyLen][1B hasKDF][? KDF data][1B hasMetadata][? metadata][1B algoID][nonce]`
- **EncryptFile** reads a file and returns `(encrypted []byte, error)` with header prepended
- **DecryptFile** reads a file and returns `(plaintext []byte, header *Header, error)`
- **EncryptFileBytes** operates on raw bytes (used for manifest encryption)
- **DecryptFileBytes** operates on raw bytes and returns `(plaintext, *Header, error)`
- Age algorithm uses asymmetric keys (recipient/identity) rather than passphrase
- Metadata is optional; controlled by `EmbedMetadata` in `EncryptFileOptions`
- Header version is always 1 (no backward compat needed, pre-release)

## Building

```bash
make build-cli      # CLI binary only (bin/kryp-windows-amd64.exe)
make build-gui      # GUI binary only (requires CGO/GCC, uses -H=windowsgui)
make build-all      # CLI cross-compile (linux/darwin/windows) + native GUI
make build-cli-all  # CLI cross-compile for all platforms
make build-gui-all  # GUI cross-compile for all platforms
```

## Testing

```bash
make test        # go vet ./... + go test -v -count=1 -timeout 120s ./internal/...
make test-e2e    # go test -count=1 -timeout 600s ./test/...
```

125+ unit tests (crypto: 93+, config: 7, db: 11, store: 14), 29 E2E tests. All must pass.

## Common Tasks

### Add new algorithm

1. Implement `Encryptor` interface in new file
2. Register in `encryptors` map in `registry.go`
3. Add tests

### Add CLI flag

1. Add global var in `cmd/cli/main.go`
2. Register in command's `Flags()` init
3. Use in `runEncrypt`/`runDecrypt`

### Add algorithm alias

1. Add entry to `algorithmAliases` map in `internal/crypto/types.go`
2. GUI and CLI auto-use `crypto.ParseAlgorithm` — no duplication

### Modify header format

- Edit `internal/crypto/header.go`
- Update `Encode()` and `DecodeHeader()`
- All tests must still pass

## Notes for AI Agents

- Never use `go build` directly — use `make build-cli` or `make build-gui`
- Never add comments to code
- Tests use `test/original/`, `test/encrypted/`, `test/decrypted/` directories
- `EncryptFileOptions` can carry `AgeRecipient`, `EmbedMetadata`, `OriginalNameHint`, `OriginalPathHint`
- ML-KEM-768 uses asymmetric keys — `KeyFile` for encrypt = public key (1184 B), for decrypt = private seed (64 B)
- ML-KEM-1024 uses asymmetric keys — `KeyFile` for encrypt = public key (1568 B), for decrypt = private seed (64 B)
- X-Wing uses asymmetric keys — `KeyFile` for encrypt = public key (1216 B), for decrypt = private seed (32 B)
- HPKE uses asymmetric keys — `KeyFile` for encrypt = public key, for decrypt = private seed
- `DecryptFileOptions` uses `KeyFile` for age identity file path
- The store package is untested — be careful with changes
- GUI requires CGO — cannot build on systems without GCC/MinGW
- GUI uses `fyne.Do()` for all UI updates — encryption/decryption runs in goroutines
- GUI key gen dialog is `dialog.CustomDialog` sized 500x500 with key text output
- GUI log entries are timestamped `[HH:MM:SS]`
- Binary naming pattern: `kryp-{os}-{arch}.exe` (Windows) / `kryp-{os}-{arch}` (Unix)
