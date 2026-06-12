# AGENTS.md — AI Agent Guide

## Project Overview

`kryp` is a Go CLI+GUI tool for encrypting/decrypting files with multiple algorithms, UUID rename, and embedded metadata. Module: `github.com/babico/kryp`.

## Key Files

| File | Purpose |
| ---- | ------- |
| `internal/crypto/header.go` | Binary header with magic bytes `ENCR`, metadata support |
| `internal/crypto/registry.go` | Public API: `EncryptFile`, `DecryptFile`, `EncryptFileBytes`, `DecryptFileBytes`, `GenerateKey`, `DetectAlgorithm`, `ListAlgorithms` |
| `internal/crypto/internal.go` | Internal helpers: `loadKey`, `resolveDecryptKey`, `readFullHeader`, `deriveKeyFromOpts`, `encryptFileBytes`, `encryptKEMBytes`, `encryptAgeBytes`, `encryptCompatible` |
| `internal/crypto/keygen.go` | Key generation: `GenerateKEMKeypair`, `ExtractPublicKey`, `GenerateKeyPairFromSeed` |
| `internal/crypto/types.go` | `AlgorithmID`, `KDFMethod` enums, `Encryptor` interface, `ParseAlgorithm`/`ParseKDF`, aliases map |
| `internal/crypto/keyderivation.go` | `DeriveKey` (Argon2id/scrypt/PBKDF2), `GenerateSalt`, KDF param encode helpers |
| `internal/crypto/symmetric/` | Symmetric ciphers: 11 implementations (XChaCha20, ChaCha20, AES-GCM, SecretBox, AES-CTR+HMAC, AEGIS-128L, AEGIS-256, AES-GCM-SIV, AES-SIV, ASCON-128, Xoodyak, Deoxys-II) |
| `internal/crypto/asymmetric/` | Asymmetric ciphers: Age (age), HPKE (hpke) |
| `internal/crypto/pqc/` | Post-quantum ciphers: ML-KEM-768, ML-KEM-1024, X-Wing, HQC-128, FrodoKEM-640-SHAKE |
| `internal/crypto/core/` | Core types: `AlgorithmID.String()`, `KDFMethod.String()`, `EncryptionResult`, `Encryptor` interface |
| `cmd/cli/main.go` | Entry point, `Version`, 29 global flag variables |
| `cmd/cli/commands.go` | Cobra command constructors (10 commands): encrypt, decrypt, list, algorithms, genkey, init, version, inspect, hash, info |
| `cmd/cli/actions.go` | `runEncrypt`, `runDecrypt`, `runList` (515 lines, needs refactoring) |
| `cmd/cli/helpers.go` | Shared helpers: `ensureExtension`, `outputPathForFile`, `readFilesFrom`, `detectMode`, `encryptTrain`, `decryptTrain`, `generateAgeKey`, `resolveConfig` |
| `cmd/gui/main.go` | Entry point, `guiApp` struct, `Version` (duplicated from CLI) |
| `cmd/gui/actions.go` | `runEncrypt`, `runDecrypt`, `runDecryptFiles`, `generateKEMKeypair` |
| `cmd/gui/dialogs.go` | Key generation dialog (231 lines, needs refactoring) |
| `cmd/gui/ui.go` | Tab builders, `browseFolder`, `makeSection`, `buildRightColumn` |
| `cmd/gui/widgets.go` | `atomicBool`, `logList`, log/running helpers (race condition in `Append`) |
| `internal/db/manifest.go` | UUID manifest database with sync.RWMutex |
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

## Known Issues / Traps

### Critical
- **`ExtractPublicKey` misidentification** (`keygen.go:129-171`): Cannot distinguish ML-KEM-768 from ML-KEM-1024 (both 64-byte seeds), nor X-Wing from HPKE (both 32-byte seeds). Length-based detection is fundamentally broken. FrodoKEM entirely missing from `ExtractPublicKey`. Avoid calling `ExtractPublicKey` without explicit algorithm parameter.
- **KDF parameter downgrade attack** (`keyderivation.go:44-69`): KDF parameters in the unauthenticated header have no minimum enforcement on decrypt. An attacker can set iterations to 1 for fast brute-force. Mitigation: validate minimum parameters on decrypt or include KDF params in AEAD authenticated data.

### High
- **Race condition** (`widgets.go:51-56`): `logList.Append` calls `Refresh()` outside the mutex while UI reads `ll.lines` without synchronization.
- **Manifest not encrypted for Age** (`actions.go:192-219`): When using Age algorithm with `Database.Encrypt=true`, the manifest saves as plain `manifest.json` instead of encrypted `manifest.json.enc`.
- **Nil deref risk** (`commands.go:89,354`): `GetEncryptor` error silently ignored; returns nil, causing panic on next call.
- **Silent mkdir failures** (`gui/actions.go`: 5 places): `os.MkdirAll` errors ignored.
- **Sscanf returns ignored** (`gui/actions.go:63-69`): Custom KDF parameters read without validating scan count.
- **`printKEMKeypairOutput` swallows errors** (`helpers.go:26-33`): Write failures silently lost; caller has no way to detect.

### Medium
- **Passphrase in world-readable config** (`config.go:87`): `Save` writes config with `0644` permissions.
- **Config passphrase in env var** (`config.go:91-96`): `ENCRYPT_CLI_PASSPHRASE` leaks into process listings.
- **Hardcoded algorithm lists** in GUI (`dialogs.go:20`, `ui.go:111`): Won't include new algorithms added to registry.
- **`version` duplicated** between `cmd/cli/main.go` and `cmd/gui/main.go` — should share via `internal/version`.
- **OOM risk** (`commands.go:325`): `hashCmd` loads entire file into memory via `os.ReadFile`.
- **`version` flag collision** (`commands.go:48,68`): `-c` short flag works only on encrypt/decrypt; `--config` works globally.
- **DecodeHeader doesn't use MagicBytes** (`header.go:134`): Hardcodes `'E'`, `'N'`, `'C'`, `'R'` instead of package constant.
- **AES-SIV misuse** (`aes_siv.go`): Generates random nonce for SIV (deterministic AEAD) — wasteful overhead.
- **`Nonce` field overload**: PQC and HPKE encryptors store KEM ciphertext in the `Nonce` field, which is semantically misleading.

## Security Notes
- Never use `EncryptFileOptions.Passphrase` as a Go string — convert from `[]byte` at the point of input and `MemClr` after use.
- KDF parameters stored in header are NOT authenticated. Do not trust them without validation on decrypt.
- The `keygen.go:ExtractPublicKey` function MUST receive an explicit algorithm parameter; do not rely on its length-based heuristic.

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

**Known test coverage gaps:**
- AEGIS-128L, AEGIS-256, AES-GCM-SIV, AES-SIV, Xoodyak, Deoxys-II have zero unit tests (only exercised via Encryptor interface in registry tests)
- HQC-128 and FrodoKEM-640-SHAKE have no encrypt/decrypt E2E tests
- No ML-KEM-768 E2E test
- Wrong-key decrypt tests only cover ML-KEM-768 and age
- `TestExtractPublicKeyFrodoKEMNotSupported` uses `t.Log` instead of `t.Error` — passes even if bug is fixed

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
