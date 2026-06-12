# Contributing

## Getting Started

1. Fork the repository
2. Clone your fork
3. Run `make init` to create test directories
4. Run `make test` to verify everything works
5. Read `AGENTS.md` for architecture details and known issues

## Requirements

- Go 1.26+
- `make` (GNU Make)
- For GUI builds: GCC/MinGW-w64 (Windows), Xcode Command Line Tools (macOS), build-essential (Linux)

## Project Structure

```plaintext
cmd/
  cli/          # CLI entry point (Cobra) — main.go, commands.go, actions.go, helpers.go
  gui/          # Fyne GUI entry point — main.go, actions.go, dialogs.go, ui.go, widgets.go
internal/
  config/       # YAML configuration loading/saving
  crypto/       # Encryption algorithms, KDF, header format
    core/             # Core types: AlgorithmID, KDFMethod, EncryptionResult, Encryptor interface
    symmetric/        # Symmetric ciphers: 11 implementations
    asymmetric/       # Asymmetric ciphers: Age (X25519), HPKE (RFC 9180)
    pqc/              # Post-quantum ciphers: ML-KEM-768/1024, X-Wing, HQC-128, FrodoKEM-640
    registry.go       # Public API: EncryptFile, DecryptFile, GenerateKey, etc.
    internal.go       # Internal helpers: loadKey, deriveKeyFromOpts, encryptKEMBytes, etc.
    keygen.go         # KEM keypair generation, ExtractPublicKey, GenerateKeyPairFromSeed
    keyderivation.go  # Argon2id, scrypt, PBKDF2, GenerateSalt
    types.go          # Algorithm/KDF enums, Encryptor interface, ParseAlgorithm/ParseKDF
    header.go         # Binary header encode/decode with magic bytes
  db/           # UUID manifest database with sync.RWMutex
test/
  e2e_test.go         # End-to-end tests (37 scenarios across 5 files)
  e2e_key_test.go
  e2e_pqc_test.go
  e2e_age_test.go
  e2e_advanced_test.go
  original/           # Test input files
  encrypted/          # Test encrypted output
  decrypted/          # Test decrypted output
```

## Code Style

- Follow standard Go conventions (`gofmt`)
- No comments in code (see AGENTS.md)
- Use existing patterns when adding new files
- Keep functions focused and small
- Always check and handle errors — never discard error return values
- Use `crypto/rand` for all cryptographic randomness
- Wrap errors with context: `fmt.Errorf("operation: %w", err)`

## Testing

```bash
make test        # Unit tests (vet + test ./internal/...)
make test-e2e    # End-to-end tests
make test-all    # All tests (unit + e2e)
make bench       # Benchmarks
make test-race   # Race detector
```

### Test Coverage Requirements

- All new algorithms MUST include:
  - Encrypt/decrypt round-trip tests
  - Wrong-key/wrong-passphrase rejection tests
  - Empty data, single-byte, and large data tests
  - Both `Encryptor` interface and `EncryptFile`/`DecryptFile` paths for asymmetric/PQC
- E2E tests MUST verify decrypt round-trip correctness, not just exit codes
- New CLI flags MUST have E2E tests

### Known Coverage Gaps

The following areas need tests:
- AEGIS-128L, AEGIS-256, AES-GCM-SIV, AES-SIV, Xoodyak, Deoxys-II (encryptor tests)
- HQC-128, FrodoKEM-640-SHAKE, ML-KEM-768 (E2E tests)
- Wrong-key decrypt for HPKE, ML-KEM-1024, X-Wing, HQC-128, FrodoKEM-640

## Adding a New Algorithm

1. Create a new file `internal/crypto/<category>/youralgo.go`
2. Implement the `Encryptor` interface (`ID`, `Encrypt`, `Decrypt`, `NonceSize`, `KeySize`)
3. Add algorithm ID to `types.go` and aliases to `algorithmAliases` map
4. Register in `encryptors` map in `registry.go`
5. Add unit tests for Encrypt/Decrypt roundtrip, edge cases, wrong-key
6. Add E2E test in `test/` directory
7. Update `docs/ALGORITHMS.md` with algorithm table entry
8. Update hardcoded algorithm lists in GUI (`dialogs.go:20`, `ui.go:111`)

## Adding Dependencies

```bash
go get <package>
make deps  # tidies go.mod and verifies
```

## Commit Messages

Use conventional commits:

```plaintext
feat: add support for ...
fix: correct ...
docs: update README ...
test: add test for ...
refactor: simplify ...
security: add minimum KDF parameter enforcement
```

## Pull Requests

- One feature/fix per PR
- Include tests
- Ensure `make test-all` passes
- Run `make fmt` before committing
- Do NOT include binary files in PRs
