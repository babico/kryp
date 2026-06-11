# Contributing

## Getting Started

1. Fork the repository
2. Clone your fork
3. Run `make init` to create test directories
4. Run `make test` to verify everything works

## Requirements

- Go 1.21+
- `make` (GNU Make)
- For GUI builds: GCC/MinGW-w64 (Windows), Xcode Command Line Tools (macOS), build-essential (Linux)

## Project Structure

```
cmd/
  cli/          # CLI entry point (Cobra)
  gui/          # Fyne GUI entry point
internal/
  config/       # YAML configuration loading/saving
    config.go         # Config struct, Load/Save/Default
    examples/         # Example config templates
  crypto/       # Encryption algorithms, KDF, header format
    types.go          # Algorithm/KDF enums, Encryptor interface, ParseAlgorithm/ParseKDF
    header.go         # Binary header encode/decode with magic bytes
    registry.go       # Algorithm registry, encrypt/decrypt functions
    keyderivation.go  # Argon2id, scrypt, PBKDF2
    xchacha20.go      # XChaCha20-Poly1305
    chacha20impl.go   # ChaCha20-Poly1305
    aesgcm.go         # AES-256-GCM
    secretbox.go      # NaCl SecretBox
    aesctrhmac.go     # AES-256-CTR + HMAC-SHA256
    age.go            # age (X25519 + ChaCha20-Poly1305)
  db/           # UUID manifest database
  store/        # Rclone uploader
test/
  e2e_test.go   # End-to-end tests
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
- All 6 algorithms with encrypt/decrypt round-trips
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
5. Add CLI parsing in `cmd/cli/main.go`

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
