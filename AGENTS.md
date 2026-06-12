# AGENTS.md — AI Agent Guide

## Project Overview

`kryp` is a Go CLI+GUI tool for encrypting/decrypting files with multiple algorithms, UUID rename, and embedded metadata. Module: `github.com/babico/kryp`.

## Key Files

| File | Purpose |
| ---- | ------- |
| `internal/crypto/header.go` | Binary header with magic bytes `ENCR`, metadata support |
| `internal/crypto/registry.go` | Public API: `EncryptFile`, `DecryptFile`, `EncryptFileBytes`, `DecryptFileBytes`, `GenerateKey` |
| `internal/crypto/internal.go` | Internal helpers: `loadKey`, `resolveDecryptKeyForAlgo`, `deriveKeyFromOpts` |
| `internal/crypto/keygen.go` | Key generation: `GenerateKEMKeypair`, `ExtractPublicKey`, `GenerateKeyPairFromSeed` |
| `internal/crypto/types.go` | `AlgorithmID`, `KDFMethod` enums, `Encryptor` interface, `ParseAlgorithm`/`ParseKDF` |
| `internal/crypto/keyderivation.go` | `DeriveKey` (Argon2id/scrypt/PBKDF2) |
| `internal/crypto/symmetric/` | Symmetric ciphers (XChaCha20, ChaCha20, AES-GCM, SecretBox, AES-CTR+HMAC, AEGIS-128L, AEGIS-256, AES-GCM-SIV, AES-SIV, ASCON-128, Xoodyak, Deoxys-II) |
| `internal/crypto/asymmetric/` | Asymmetric ciphers (Age, HPKE) |
| `internal/crypto/pqc/` | Post-quantum ciphers (ML-KEM-768, ML-KEM-1024, X-Wing, HQC-128, FrodoKEM-640-SHAKE) |
| `internal/crypto/core/` | Core types: `AlgorithmID.String()`, `KDFMethod.String()`, `EncryptionResult` |
| `cmd/cli/main.go` | Entry point, `Version`, global flag vars |
| `cmd/cli/commands.go` | Cobra command constructors (10 commands) |
| `cmd/cli/actions.go` | `runEncrypt`, `runDecrypt`, `runList` |
| `cmd/cli/helpers.go` | Shared helpers: `ensureExtension`, `outputPathForFile`, `decryptOutputPath`, `readFilesFrom`, `detectMode`, etc. |
| `cmd/gui/main.go` | Entry point, `guiApp` struct, `Version` |
| `cmd/gui/actions.go` | `runEncrypt`, `runDecrypt`, `generateKEMKeypair` |
| `cmd/gui/dialogs.go` | Key generation dialog modal |
| `cmd/gui/ui.go` | Tab builders, `browseFolder`, `makeSection`, `buildRightColumn` |
| `cmd/gui/widgets.go` | `atomicBool`, `logList`, log/running helpers |
| `internal/db/manifest.go` | UUID manifest database |
| `internal/config/config.go` | YAML config struct, `ApplyEnvOverrides` for `ENCRYPT_CLI_PASSPHRASE`/`ENCRYPT_CLI_KEY_FILE` |
| `docs/examples/*.yaml` | Configuration examples (basic, advanced) |
| `test/e2e_test.go` | Main E2E test runner + 7 basic passphrase tests |
| `test/e2e_key_test.go` | 4 key-based E2E tests |
| `test/e2e_pqc_test.go` | 8 PQC + ASCON E2E tests |
| `test/e2e_age_test.go` | 3 age E2E tests |
| `test/e2e_advanced_test.go` | 13 advanced E2E tests |

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

190+ unit tests (crypto: 170+, config: 11, db: 11), 37 E2E tests. All must pass.

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
- HQC-128 uses asymmetric keys — `KeyFile` for encrypt = public key, for decrypt = private seed
- FrodoKEM-640-SHAKE uses asymmetric keys — `KeyFile` for encrypt = public key (9616 B), for decrypt = private key (19888 B)
- `DecryptFileOptions` uses `KeyFile` for age identity file path
- GUI requires CGO — cannot build on systems without GCC/MinGW
- GUI uses `fyne.Do()` for all UI updates — encryption/decryption runs in goroutines
- GUI key gen dialog is `dialog.CustomDialog` sized 500x500 with key text output
- GUI log entries are timestamped `[HH:MM:SS]`
- Binary naming pattern: `kryp-{os}-{arch}.exe` (Windows) / `kryp-{os}-{arch}` (Unix)
