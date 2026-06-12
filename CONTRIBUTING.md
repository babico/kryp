# Contributing

## Getting Started

1. Fork the repository
2. Clone your fork
3. Run `make init` to create test directories
4. Run `make test` to verify everything works

## Requirements

- Go 1.26+
- `make` (GNU Make)
- For GUI builds: GCC/MinGW-w64 (Windows), Xcode Command Line Tools (macOS), build-essential (Linux)

## Project Structure

```
cmd/
  cli/          # CLI entry point (Cobra) — main.go, commands.go, actions.go, helpers.go
  gui/          # Fyne GUI entry point — main.go, actions.go, dialogs.go, ui.go, widgets.go
internal/
  config/       # YAML configuration loading/saving
  crypto/       # Encryption algorithms, KDF, header format
    core/             # Core types: AlgorithmID, KDFMethod, EncryptionResult
    symmetric/        # Symmetric ciphers (XChaCha20, ChaCha20, AES-GCM, etc.)
    asymmetric/       # Asymmetric ciphers (Age, HPKE)
    pqc/              # Post-quantum ciphers (ML-KEM, X-Wing, HQC, FrodoKEM)
    registry.go       # Public API: EncryptFile, DecryptFile, etc.
    internal.go       # Internal helpers: loadKey, deriveKeyFromOpts
    keygen.go         # KEM keypair generation, ExtractPublicKey
    keyderivation.go  # Argon2id, scrypt, PBKDF2
    types.go          # Algorithm/KDF enums, Encryptor interface, ParseAlgorithm/ParseKDF
    header.go         # Binary header encode/decode with magic bytes
  db/           # UUID manifest database
test/
  e2e_test.go         # End-to-end tests (37 scenarios across 5 files)
  e2e_key_test.go
  e2e_pqc_test.go
  e2e_age_test.go
  e2e_advanced_test.go
```

## Code Style

- Follow standard Go conventions (`gofmt`)
- No comments in code unless explaining non-obvious behavior
- Use existing patterns when adding new files
- Keep functions focused and small

## Testing

```bash
make test        # Unit tests
make test-e2e    # End-to-end tests  
make test-all    # All tests
make bench       # Benchmarks
```

E2E tests cover:
- All 19 algorithms with encrypt/decrypt round-trips
- All 3 KDF methods
- Raw key encryption
- UUID rename mode
- Wrong passphrase rejection
- Large file (5MB)
- Empty directory
- Algorithm auto-detection

## Adding a New Algorithm

1. Create a new file `internal/crypto/youralgo.go`
2. Implement the `Encryptor` interface
3. Add the algorithm to `encryptors` map in `registry.go`
4. Add tests in `crypto_test.go`
5. Add CLI flag (global var in `main.go`, register in command's `Flags()` in `commands.go`, use in `actions.go`)

## Commit Messages

Use conventional commits:

```
feat: add support for ...
fix: correct ...
docs: update README ...
test: add test for ...
refactor: simplify ...
```

## Pull Requests

- One feature/fix per PR
- Include tests
- Ensure all tests pass
- Run `make fmt` before committing

## Adding Dependencies

```bash
go get <package>
make deps  # tidies go.mod and verifies
```
