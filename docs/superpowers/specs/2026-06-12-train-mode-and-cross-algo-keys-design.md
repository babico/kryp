# Train Mode + Cross-Algorithm Key Files

## Summary

Two features for the `kryp` CLI:

1. **Train mode**: Encrypt/decrypt multiple explicitly-listed files in one command, using the existing `-s` flag as a `StringSliceVar` supporting single-file, directory-walk, and multi-file modes.
2. **Cross-algorithm key files**: `genkey` without an algorithm produces a 64B universal key usable with any symmetric algorithm. PQC keypairs can be derived deterministically from a universal seed.

---

## Feature 1: Multi-File Train Mode

### CLI

```
# Existing — unchanged
kryp encrypt -s file.txt            # single file
kryp encrypt -s ./dir/              # directory walk (auto-detect)

# New — multiple files via -s slice
kryp encrypt -s a.txt b.jpg         # explicit file list (train mode)
kryp decrypt -s a.enc b.enc         # train decrypt
kryp encrypt --files-from list.txt  # file list from text file

# Same for decrypt
kryp decrypt -s a.enc b.enc -o out/ --key-file key.bin
kryp decrypt --files-from enc-files.txt -o out/ --key-file key.bin
```

### Detection logic (runtime)

```
if --files-from given:
    read paths from file → train mode
elif -s has >1 value:
    train mode
elif -s has 1 value, it's a directory:
    directory walk mode (existing)
elif -s has 1 value, it's a file:
    single-file mode (existing)
else:
    error: no source specified
```

Priority: `--files-from` > multiple `-s` > single `-s` (dir) > single `-s` (file)

### Behavior in train mode

- **No directory walking** — each path is encrypted/decrypted as-is
- **Encrypt output**: `<output-dir>/<basename>.enc` (if output-dir given) or next to source with `.enc` suffix
- **Decrypt output**: `<output-dir>/<original-name>` (from header metadata or stripping `.enc`)
- **No manifest** generated for encrypt
- **No manifest lookup** for decrypt — each file's header is read individually for algorithm + original name
- **Error handling**: errors are collected per-file, not fatal — continue processing remaining files. Summary printed at end.
- **Output dir**: created if not exists (same as current directory mode)

### `--files-from` format

```
# File list — one path per line
# Comments start with #
blank lines are skipped

/path/to/file1.txt
../relative/path/file2.jpg
C:\absolute\path\file3.pdf
```

### Changes required

#### CLI (`cmd/cli/main.go`)

- `-s` / `--source`: change from `StringVar` to `StringSliceVar`
- Add `--files-from` flag (`StringVar`)
- `runEncrypt` — detect mode, dispatch to existing or new helpers
- `runDecrypt` — detect mode, dispatch to existing or new helpers
- New `encryptFiles(paths []string, outputDir string, opts *EncryptFileOptions)` helper
- New `decryptFiles(paths []string, outputDir string, opts *DecryptFileOptions)` helper
- `genkeyCmd` — make algorithm arg optional (see Feature 2)

#### Internal (`internal/crypto/registry.go`)

- No changes needed — `EncryptFile` / `DecryptFile` already work per-file

#### GUI (`cmd/gui/main.go`)

- File dialog: multi-select mode for file picker
- Process loop: iterate over selected files, show progress per file

---

## Feature 2: Cross-Algorithm Key Files

### Universal key seed

```
kryp genkey key.bin                  # 64B universal key (no algorithm)
kryp genkey aes-256-gcm key.bin      # 32B algorithm-specific (existing)
kryp genkey raw key.bin --size 32    # explicit size (optional)
```

- If 1 positional arg (output path only) → produce 64B universal key
- If 2 positional args (algorithm + output path) → existing behavior (random key or keypair)
- If 2 positional args (algorithm + output path) + `--seed-file <path>` → deterministic PQC keypair
- Universal key = 64B random bytes — covers the largest symmetric key size (AES-256-CTR+HMAC, AES-256-SIV)

### Deterministic PQC keypairs from seed

```
kryp genkey frodokem-640-shake keys/ --seed-file key.bin
kryp genkey ml-kem-768 keys/ --seed-file key.bin
```

Design: 3rd positional arg is replaced by `--seed-file <path>` flag for cleaner parsing.

- Reads entire seed file  
- For ML-KEM: first 64B → `mlkem.NewDecapsulationKey768(seed)` → deterministic keypair
- For HQC-128: first 2306B (SeedSize128) → `hqc.NewKey128FromSeed(seed)` → deterministic keypair
- For FrodoKEM: override `rng` function to read from seed → `fk.Keygen()` → deterministic keypair
- For X-Wing: first 32B → `xwing.NewDecapsulationKey(seed)` → deterministic keypair
- For HPKE: first 32B → use as private key seed → `scheme.DeriveKeyPair(seed)`
- Private key file + `.pub` public key file written to `<output>/` directory
- Without `--seed-file` → random generation (existing behavior)

### Compatible mode (interop with other tools)

New `--compatible` flag on `encrypt`: skips the kryp `[ENCR header + nonce]` wrapper, outputs **raw standard format** for the algorithm.

```
kryp encrypt -s file.txt --algorithm aes-256-gcm --key-file key.bin --compatible -o file.enc
# Output: [12B nonce][ciphertext+tag] — decryptable with OpenSSL

kryp encrypt -s file.txt --algorithm secretbox --passphrase "pw" --compatible -o file.enc
# Output: [24B nonce][ciphertext] — decryptable with libsodium

kryp encrypt -s file.txt --algorithm age --age-recipient "age1..." --compatible -o file.enc
# Output: raw age file (age already has its own format, no change needed)
```

Implementation detail: when `--compatible`, the `encryptFileBytes` skips header creation. The `EncryptionResult` is written directly to output.

- Compatible mode disables: UUID rename, manifest generation, metadata embedding
- Key derivation still applies (Argon2id/scrypt/PBKDF2), but no KDF metadata is stored — user must remember params
- Recommended: use `--key-file` with `--compatible` to avoid passphrase/KDF parameter management
- Incompatible flags produce error: `--uuid-rename`, `--embed-metadata`, `--files-from` (with manifest)

### Raw payload documentation

For files encrypted **without** `--compatible` (standard kryp format), the header structure is:

```
Offset  Size  Field
0       4     Magic bytes "ENCR"
4       1     Header version (1)
5       4     Body length (uint32 BE)
9       N     Header body (KDF + metadata + algoID + nonce)
9+N     -     Raw ciphertext (algorithm-specific format)
```

Body structure:
```
0       1     hasKDF (0 or 1)
1       ?     KDF data (if hasKDF=1: [1B method][2B saltLen][salt][2B paramLen][params])
?       1     hasMetadata (0 or 1)
?       ?     Metadata (if hasMetadata=1: [1B flags][2B nameLen][name][2B pathLen][path])
?       1     Algorithm ID
?       N     Nonce bytes (remaining body)
```

To extract raw ciphertext:

```bash
# Method 1: Use kryp inspect to get header size
kryp inspect file.enc | grep "Header size"
dd if=file.enc bs=1 skip=<header_size> of=raw.bin

# Method 2: Parse header manually (Python)
python3 -c "
import sys
with open(sys.argv[1], 'rb') as f:
    data = f.read()
    body_len = int.from_bytes(data[5:9], 'big')
    raw = data[9+body_len:]
    sys.stdout.buffer.write(raw)
" file.enc > raw.bin

# Method 3: PowerShell
$data = Get-Content file.enc -AsByteStream -Raw
$bodyLen = [System.BitConverter]::ToUInt32($data[5..8], 0) -as [bigendian]
$raw = $data[(9+$bodyLen)..$($data.Length-1)]
[System.IO.File]::WriteAllBytes('raw.bin', $raw)
```

Once extracted, the raw ciphertext format per algorithm:

| Algorithm | Nonce | Payload | Total overhead |
|-----------|-------|---------|----------------|
| AES-256-GCM | 12B | ciphertext + 16B tag | 28B |
| ChaCha20-Poly1305 | 12B | ciphertext + 16B tag | 28B |
| XChaCha20-Poly1305 | 24B | ciphertext + 16B tag | 40B |
| SecretBox (XSalsa20-Poly1305) | 24B | ciphertext + 16B tag | 40B |
| AES-256-CTR+HMAC | 16B IV | ciphertext + 32B HMAC | 48B |
| ASCON-128 | 16B | ciphertext + 16B tag | 32B |
| Xoodyak | 16B | ciphertext + 16B tag | 32B |
| AEGIS-128L | 16B | ciphertext + 16B tag | 32B |
| AEGIS-256 | 32B | ciphertext + 16B tag | 48B |
| AES-256-GCM-SIV | 12B | ciphertext + 16B tag | 28B |
| AES-256-SIV | 16B | ciphertext + 16B tag | 32B |
| Deoxys-II-256-128 | 15B | ciphertext + 16B tag | 31B |

### Recovery: public from private

```
kryp genkey --extract-public keys/mlkem768
```

Algorithm detection by private key size:

| Algorithm | Private key size |
|-----------|-----------------|
| ML-KEM-768 | 64 B |
| ML-KEM-1024 | 64 B |
| X-Wing | 32 B |
| HPKE (X25519) | 32 B |
| HQC-128 | 2321 B |
| FrodoKEM-640-SHAKE | 19888 B |

Resolution: try each parser in order of key size. For same-size algorithms (ML-KEM-768 vs ML-KEM-1024 / X-Wing vs HPKE), try both — the one that succeeds wins. If both succeed (unlikely), output first match.

- Writes `.pub` file in same directory as private key
- Supported for all 6 KEM algorithms

### On-the-fly key slicing

- During encrypt with `--key-file`, `loadKey()` reads the file and truncates to `KeySize()` bytes of the chosen algorithm
- A 64B universal key works with any symmetric algorithm (takes first N bytes)
- A 32B key file works with 32B and 16B algorithms (takes first N bytes)
- If key file is shorter than `KeySize()` → error: "key file too short: need X bytes, got Y"
- Key file can be longer than needed — extra bytes are ignored

### Changes required

#### `cmd/cli/main.go`

- `genkeyCmd` — make algorithm arg optional:
  - 0 args: print help
  - 1 arg (output): generate 64B universal key
  - 2 args (algorithm, output): existing behavior
- Add `--seed-file` flag for deterministic PQC keygen
- Add `--extract-public` flag for public key recovery
- Add `--compatible` flag to encrypt command
- Add `--files-from` flag to encrypt/decrypt

#### `internal/crypto/registry.go`

- No changes to `loadKey` / `deriveKey` — slicing already works
- Add `ExtractPublicKey(keyPath string) (*KEMKeypair, error)`
- Add `GenerateKeyPairFromSeed(algo AlgorithmID, seed []byte) (*KEMKeypair, error)`

#### `internal/registry.go` (compatible mode)

- New helper: `encryptCompatible(data, opts)` — wraps algorithm's Encrypt, writes raw output without header
- Modified `encryptFileBytes` — if `opts.Compatible`, skip header

#### `internal/crypto/core/core.go`

- Add `Compatible bool` field to `EncryptFileOptions`

### Key size reference

| Key size | Algorithms |
|----------|-----------|
| 16 B | ASCON-128, Xoodyak |
| 32 B | XChaCha20, ChaCha20, AES-GCM, SecretBox, AEGIS-128L, AEGIS-256, GCM-SIV, Deoxys-II |
| 64 B | AES-256-CTR+HMAC, AES-256-SIV (universal) |

---

## GUI Support

All features must be reflected in the Fyne GUI (`cmd/gui/main.go`):

1. **Train mode**: Encrypt/decrypt dialogs support multi-select file dialog. Each file is processed in a loop with status updates in log area.
2. **Universal key gen**: Key gen dialog — when no algorithm selected, defaults to 64B universal key file.
3. **Seed-based PQC key gen**: Add "Seed file" input field in key gen dialog. When a seed file path is entered, key generation is deterministic (uses seed instead of random).
4. **Extract public key**: Add "Extract Public Key" button that opens a file dialog to select a private key, then recovers and saves the public key.
5. **Cross-algo key usage**: When a key file is selected for encryption, any algorithm can be chosen regardless of key size (key is sliced to fit).
6. **Compatible mode**: Add "Compatible mode (no header)" checkbox in encrypt dialog. When checked, disables UUID rename and metadata options.
7. **Respect `--compatible` in encrypt flow**: If compatible is checked, skip header creation, write raw ciphertext directly.

---

## Errors & Edge Cases

| Scenario | Behavior |
|----------|----------|
| Train encrypt: one path fails (permissions) | Log error, continue with remaining files, print summary at end |
| Train decrypt: file is not valid kryp format | Log "skipping: not a kryp file", continue |
| `--files-from` file not found | Fatal error before processing any files |
| `--files-from` contains paths that don't exist | Per-file error, continue |
| `--compatible` + `--uuid-rename` | Error: incompatible flags |
| `--compatible` + `--embed-metadata` | Error: incompatible flags |
| `--compatible` + PQC algorithm (ml-kem, hqc, frodo) | Error: compatible mode only for symmetric + age |
| `genkey` with 2 args + `--seed-file` but algorithm is symmetric | Use seed as raw key material — write directly to output |
| `genkey --extract-public` on non-KEM key file | Error: "not a recognized private key format" |
| Key file = 0 bytes | Error: "key file too short" |
| Train mode: output dir not specified | Default to `./encrypted/` for encrypt, `./decrypted/` for decrypt |

---

## Testing

### Unit tests (`internal/...`)

1. **`ExtractPublicKey`** — for each KEM algorithm:
   - Generate keypair → `ExtractPublicKey(privateKeyPath)` → returned public key matches original
   - Invalid path → error
   - Non-KEM file → error

2. **`GenerateKeyPairFromSeed`** — for each KEM algorithm:
   - Call twice with same seed → identical keypair
   - Call with different seed → different keypair
   - Invalid seed size → error

3. **`encryptCompatible`** — for each symmetric algorithm:
   - Output is exactly `[nonce][ciphertext+tag]` — no ENCR header
   - Can be decrypted with bare algorithm Decrypt (no header)

4. **Key slicing** — `loadKey`:
   - 64B file with 32B algo → returns first 32B
   - 32B file with 32B algo → returns all 32B
   - 16B file with 32B algo → error

### CLI tests (`test/...`)

5. **Train encrypt** (3 files):
   - `kryp encrypt -s f1.txt f2.txt f3.txt -o enc/ --key-file key.bin`
   - Verify: `enc/f1.txt.enc`, `enc/f2.txt.enc`, `enc/f3.txt.enc` exist
   - Verify: no `manifest.json` produced

6. **Train decrypt** (3 files):
   - `kryp decrypt -s enc/f1.txt.enc enc/f2.txt.enc enc/f3.txt.enc -o dec/ --key-file key.bin`
   - Verify SHA256 of decrypted files matches originals

7. **`--files-from` encrypt:**
   - `echo -e "f1.txt\nf2.txt\n# comment\n\nf3.txt" > list.txt`
   - `kryp encrypt --files-from list.txt -o enc/ --passphrase "pw"`
   - Verify all 3 files encrypted

8. **`--files-from` decrypt:**
   - `kryp decrypt --files-from list.txt -o dec/ --passphrase "pw"`

9. **Single file via `-s` (backward compat)**:
   - `kryp encrypt -s f1.txt -o enc/ --key-file key.bin`
   - Same as before — verify works

10. **Directory via `-s` (backward compat)**:
    - `kryp encrypt -s test/original/ -o enc/ --passphrase "pw"`
    - Same as before — verify manifest created

11. **Universal key:**
    - `kryp genkey uni.bin` → 64B
    - `kryp encrypt -s f1.txt --algorithm aes-256-gcm --key-file uni.bin` → works (takes first 32B)
    - `kryp encrypt -s f1.txt --algorithm ascon --key-file uni.bin` → works (takes first 16B)

12. **Deterministic PQC:**
    - `kryp genkey ml-kem-768 kemkeys/ --seed-file uni.bin`
    - Run twice → identical `.pub` and private key files

13. **Extract public:**
    - `kryp genkey ml-kem-768 keys/`
    - `kryp genkey --extract-public keys/mlkem768`
    - Verify `keys/mlkem768.pub` matches originally generated `.pub`

14. **Compatible mode:**
    - `kryp encrypt -s f1.txt --key-file key.bin --compatible -o f1.enc`
    - Verify first 4 bytes are NOT `ENCR`
    - Decrypt with: `kryp decrypt -s f1.enc -o f1 --key-file key.bin` → should fail (no header)
    - Decrypt with custom script / OpenSSL demo

15. **Key file too short:**
    - Create 16B key: `kryp genkey 16b.key` (universal 64B)... need explicit small test
    - `kryp encrypt -s f1.txt --algorithm aes-256-gcm --key-file 16b.key` → error

16. **Mixed `-s` modes:**
    - `kryp encrypt -s a.txt b.txt -o out/ --passphrase "pw"` → train mode (2 files)
    - `kryp encrypt -s ./dir/ --passphrase "pw"` → directory mode (1 directory arg)
    - `kryp encrypt -s file.txt --passphrase "pw"` → single file mode

17. **GUI encrypt multiple files:**
    - Open encrypt dialog → select 3 files → encrypt → verify 3 output files

18. **GUI universal key gen:**
    - Key gen dialog → leave algorithm empty → generate → file is 64B

19. **GUI compatible mode:**
    - Check "Compatible mode" → UUID rename / metadata options disabled

20. **GUI extract public key:**
    - Select private key file → extract → `.pub` file created

21. **Cross-algo encrypt roundtrip:**
    - `kryp genkey uni.bin` (64B)
    - Encrypt with aes-256-gcm using uni.bin
    - Encrypt with xchacha20 using uni.bin  
    - Both succeed, decrypt each with correct algorithm
