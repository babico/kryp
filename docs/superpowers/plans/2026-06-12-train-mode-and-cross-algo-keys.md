# Train Mode + Cross-Algorithm Key Files Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add multi-file train mode, cross-algorithm key file usage, deterministic PQC keygen from seed, and compatible mode.

**Architecture:** Changes are spread across CLI (flag changes + mode dispatch), internal crypto (compatible mode, extract public key, seed-based keygen), and GUI (multi-select, new options).

**Tech Stack:** Go, Cobra CLI, Fyne v2 GUI

---

## File Structure

| File | Change |
|------|--------|
| `internal/crypto/core/core.go` | Add `Compatible bool` field to `EncryptFileOptions` |
| `internal/crypto/registry.go` | Add `encryptCompatible()`, `ExtractPublicKey()`, `GenerateKeyPairFromSeed()` |
| `cmd/cli/main.go` | `-s` → `StringSliceVar`, `--files-from`, train encrypt/decrypt, genkey changes, `--compatible`, `--extract-public`, `--seed-file` |
| `cmd/gui/main.go` | Multi-file dialog, universal key gen, seed field, extract public button, compatible checkbox |
| `docs/ALGORITHMS.md` | Add raw payload format documentation + stripping instructions |
| `internal/crypto/symmetric/*` | Export nonce/tag sizes per algorithm for documentation constants |

---

### Task 0: Add Compatible field to EncryptFileOptions

**Files:**
- Modify: `internal/crypto/core/core.go`

- [ ] **Step 1: Add Compatible bool field**

Edit `internal/crypto/core/core.go` — add `Compatible` to `EncryptFileOptions`:

```go
type EncryptFileOptions struct {
    Algorithm       AlgorithmID
    Passphrase      []byte
    KeyFile         string
    KDFMethod       KDFMethod
    UUIDRename      bool
    EmbedMetadata   bool
    AgeRecipient    string
    OriginalNameHint string
    OriginalPathHint string
    Argon2Time      uint32
    Argon2Memory    uint32
    Argon2Threads   uint8
    ScryptN         uint32
    ScryptR         uint32
    ScryptP         uint32
    PBKDF2Iter      uint32
    Compatible      bool // NEW — raw output without kryp header
}
```

- [ ] **Step 2: Run tests to verify no regression**

Run: `go vet ./internal/crypto/core/...`
Expected: clean

---

### Task 1: Add encryptCompatible helper to registry.go

**Files:**
- Modify: `internal/crypto/registry.go`

- [ ] **Step 1: Add encryptCompatible function**

At the end of `registry.go`, add:

```go
func encryptCompatible(data []byte, opts *EncryptFileOptions) ([]byte, error) {
    opts.Algorithm.OnlySymmetricAlgos()
    if opts.EmbedMetadata {
        return nil, errors.New("--compatible is incompatible with --embed-metadata")
    }
    if opts.UUIDRename {
        return nil, errors.New("--compatible is incompatible with --uuid-rename")
    }

    enc, err := GetEncryptor(opts.Algorithm)
    if err != nil {
        return nil, err
    }

    key, err := deriveKeyFromOpts(opts, enc.KeySize())
    if err != nil {
        return nil, err
    }

    result, err := enc.Encrypt(data, key)
    if err != nil {
        return nil, err
    }

    // Compatible output: nonce || ciphertext (no ENCR header)
    return append(result.Nonce, result.Ciphertext...), nil
}
```

- [ ] **Step 2: Modify encryptFileBytes to route to encryptCompatible**

In `encryptFileBytes`, add check at top of function:

```go
func encryptFileBytes(data []byte, opts *EncryptFileOptions) ([]byte, error) {
    if opts.Compatible {
        if opts.Algorithm == AlgoAge {
            return encryptAgeBytes(data, opts)
        }
        return encryptCompatible(data, opts)
    }
    // ... rest of existing function
}
```

- [ ] **Step 3: Run tests**

Run: `go test -count=1 -timeout 120s ./internal/crypto/...`
Expected: all pass

---

### Task 2: Add ExtractPublicKey and GenerateKeyPairFromSeed

**Files:**
- Modify: `internal/crypto/registry.go`

- [ ] **Step 1: Add algorithm-by-key-size detection helper**

```go
type kemInfo struct {
    algorithm    AlgorithmID
    privateSize  int
    publicSize   int
}

var kemAlgos = []kemInfo{
    {AlgoMLKEM768, 64, 1184},
    {AlgoMLKEM1024, 64, 1568},
    {AlgoHybridXWing, 32, 1216},
    {AlgoHPKE, 32, 32},
    {AlgoHQC128, hqc.SecretKeySize128, hqc.PublicKeySize128},
    {AlgoFrodo640SHAKE, go_frodokem.Frodo640SHAKE().SecretKeyLen(), go_frodokem.Frodo640SHAKE().PublicKeyLen()},
}
```

- [ ] **Step 2: Implement ExtractPublicKey**

```go
func ExtractPublicKey(keyPath string) (*KEMKeypair, error) {
    data, err := os.ReadFile(keyPath)
    if err != nil {
        return nil, err
    }

    // Try each KEM by private key size
    var matchedAlgo AlgorithmID
    for _, k := range kemAlgos {
        if len(data) == k.privateSize {
            matchedAlgo = k.algorithm
            break
        }
    }
    // For same-size algos (ML-KEM-768 vs 1024, X-Wing vs HPKE), try both
    // ...

    switch matchedAlgo {
    case AlgoMLKEM768:
        dk, err := mlkem.NewDecapsulationKey768(data)
        if err != nil {
            return nil, err
        }
        return &KEMKeypair{
            Algorithm:   AlgoMLKEM768,
            PrivateSeed: dk.Bytes(),
            PublicKey:   dk.EncapsulationKey().Bytes(),
        }, nil
    case AlgoMLKEM1024:
        dk, err := mlkem.NewDecapsulationKey1024(data)
        if err != nil {
            return nil, err
        }
        return &KEMKeypair{
            Algorithm:   AlgoMLKEM1024,
            PrivateSeed: dk.Bytes(),
            PublicKey:   dk.EncapsulationKey().Bytes(),
        }, nil
    case AlgoHybridXWing:
        dk, err := xwing.GenerateKey() // needs seed, not raw key
        // ... X-Wing recovery from seed
    case AlgoHPKE:
        // HPKE recovery from private bytes
    case AlgoHQC128:
        dk, err := hqc.ParseDecapsulationKey128(data)
        if err != nil {
            return nil, err
        }
        return &KEMKeypair{
            Algorithm:   AlgoHQC128,
            PrivateSeed: dk.Bytes(),
            PublicKey:   dk.EncapsulationKey().Bytes(),
        }, nil
    case AlgoFrodo640SHAKE:
        // FrodoKEM private key contains public key components internally
        // Need to regenerate from the seed portion
        return nil, errors.New("FrodoKEM public key extraction not yet supported")
    default:
        return nil, errors.New("not a recognized private key format")
    }
}
```

Wait — this is getting complex. The `kemInfo` slice with same-key-size algos (MLKEM768 vs MLKEM1024 both 64B) needs actual parsing. Let me simplify:

For each KEM, try the parser and see which succeeds. Return first success.

```go
func ExtractPublicKey(keyPath string) (*KEMKeypair, error) {
    data, err := os.ReadFile(keyPath)
    if err != nil {
        return nil, err
    }

    // Try ML-KEM-768 (64B seed)
    if len(data) == 64 {
        if dk, err := mlkem.NewDecapsulationKey768(data); err == nil {
            return &KEMKeypair{
                Algorithm:   AlgoMLKEM768,
                PrivateSeed: dk.Bytes(),
                PublicKey:   dk.EncapsulationKey().Bytes(),
            }, nil
        }
        // ML-KEM-1024 also takes 64B seed
        if dk, err := mlkem.NewDecapsulationKey1024(data); err == nil {
            return &KEMKeypair{
                Algorithm:   AlgoMLKEM1024,
                PrivateSeed: dk.Bytes(),
                PublicKey:   dk.EncapsulationKey().Bytes(),
            }, nil
        }
    }

    // Try X-Wing (32B seed)
    if len(data) == 32 {
        if dk, err := xwing.GenerateKey(); ... // can't recover from bytes directly
    }

    // Try HQC-128
    if len(data) == hqc.SecretKeySize128 {
        if dk, err := hqc.ParseDecapsulationKey128(data); err == nil {
            return &KEMKeypair{
                Algorithm:   AlgoHQC128,
                PrivateSeed: dk.Bytes(),
                PublicKey:   dk.EncapsulationKey().Bytes(),
            }, nil
        }
    }

    return nil, errors.New("not a recognized KEM private key format")
}
```

Implementation will handle X-Wing and HPKE recovery during actual coding — checking what seed-to-key APIs exist.

- [ ] **Step 3: Implement GenerateKeyPairFromSeed**

```go
func GenerateKeyPairFromSeed(algo AlgorithmID, seed []byte) (*KEMKeypair, error) {
    switch algo {
    case AlgoMLKEM768:
        if len(seed) < 64 {
            return nil, errors.New("seed too short for ML-KEM-768: need 64 bytes")
        }
        dk, err := mlkem.NewDecapsulationKey768(seed[:64])
        if err != nil {
            return nil, err
        }
        return &KEMKeypair{
            Algorithm:   AlgoMLKEM768,
            PrivateSeed: dk.Bytes(),
            PublicKey:   dk.EncapsulationKey().Bytes(),
        }, nil
    case AlgoMLKEM1024:
        if len(seed) < 64 {
            return nil, errors.New("seed too short for ML-KEM-1024: need 64 bytes")
        }
        dk, err := mlkem.NewDecapsulationKey1024(seed[:64])
        if err != nil {
            return nil, err
        }
        return &KEMKeypair{
            Algorithm:   AlgoMLKEM1024,
            PrivateSeed: dk.Bytes(),
            PublicKey:   dk.EncapsulationKey().Bytes(),
        }, nil
    case AlgoHQC128:
        // HQC supports seed-based keygen internally
        dk, err := hqc.GenerateKey128()  // TODO: find seed-based API
        // For now: use seed to replace crypto/rand in keygen if possible
        return nil, errors.New("seed-based HQC keygen not yet implemented")
    case AlgoFrodo640SHAKE:
        fk := go_frodokem.Frodo640SHAKE()
        fk.OverrideRng(func(b []byte) { copy(b, seed) })
        pk, sk := fk.Keygen()
        return &KEMKeypair{
            Algorithm:   AlgoFrodo640SHAKE,
            PrivateSeed: sk,
            PublicKey:   pk,
        }, nil
    default:
        return nil, fmt.Errorf("unsupported algorithm for seed-based keygen: %s", algo)
    }
}
```

- [ ] **Step 4: Run tests**

Run: `go test -count=1 -timeout 120s ./internal/crypto/...`
Expected: all pass

---

### Task 3: CLI — -s to StringSliceVar, --files-from, train mode encrypt

**Files:**
- Modify: `cmd/cli/main.go`

- [ ] **Step 1: Change -s flag type and add --files-from**

```go
// Change from:
cmd.Flags().StringVarP(&sourceDir, "source", "s", "", "Source file or directory")
// To:
cmd.Flags().StringSliceVarP(&sourceFiles, "source", "s", []string{}, "Source file(s) or directory")
cmd.Flags().StringVarP(&filesFrom, "files-from", "", "", "Read file list from file")
```

Add new global vars:
```go
var (
    sourceFiles  []string
    filesFrom    string
    seedFile     string
    extractPublic bool
    compatible    bool
)
```

Remove old `sourceDir` from globals.

Also add `--seed-file` to genkey, `--extract-public` to genkey, `--compatible` to encrypt.

- [ ] **Step 2: Add --files-from reader helper**

```go
func readFilesFrom(path string) ([]string, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    var files []string
    for _, line := range strings.Split(string(data), "\n") {
        line = strings.TrimSpace(line)
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        files = append(files, line)
    }
    return files, nil
}
```

- [ ] **Step 3: Add mode detection helper**

```go
type sourceMode int
const (
    modeSingleFile sourceMode = iota
    modeDirectory
    modeTrain
)

func detectSourceMode(files []string) (sourceMode, []string, error) {
    if len(filesFrom) > 0 {
        paths, err := readFilesFrom(filesFrom)
        return modeTrain, paths, err
    }
    if len(files) > 1 {
        return modeTrain, files, nil
    }
    if len(files) == 0 {
        return 0, nil, errors.New("no source specified")
    }
    info, err := os.Stat(files[0])
    if err != nil {
        return 0, nil, err
    }
    if info.IsDir() {
        return modeDirectory, files, nil
    }
    return modeSingleFile, files, nil
}
```

- [ ] **Step 4: Modify runEncrypt for train mode**

In `runEncrypt`, replace the source detection block:

```go
mode, paths, err := detectSourceMode(sourceFiles)
if err != nil {
    return err
}

switch mode {
case modeSingleFile:
    // existing single-file logic
case modeDirectory:
    // existing directory walk logic
case modeTrain:
    if compatible {
        if uuidRename || embedMetadata {
            return errors.New("--compatible is incompatible with --uuid-rename and --embed-metadata")
        }
    }
    outputDir := resolveOutputDir(sourceFiles, outputDir)
    return encryptTrain(paths, outputDir, opts, manifest)
}

// encryptTrain helper:
func encryptTrain(paths []string, outputDir string, opts *crypto.EncryptFileOptions, manifest *db.Manifest) error {
    if outputDir == "" {
        outputDir = "encrypted"
    }
    if err := os.MkdirAll(outputDir, 0755); err != nil {
        return err
    }
    var errors []error
    for _, path := range paths {
        info, err := os.Stat(path)
        if err != nil {
            errors = append(errors, fmt.Errorf("skipping %s: %w", path, err))
            continue
        }
        // EncryptFile or compatible encrypt
        encData, err := crypto.EncryptFile(path, opts)
        if err != nil {
            errors = append(errors, fmt.Errorf("encrypting %s: %w", path, err))
            continue
        }
        outPath := filepath.Join(outputDir, filepath.Base(path)+".enc")
        if err := os.WriteFile(outPath, encData, 0644); err != nil {
            errors = append(errors, fmt.Errorf("writing %s: %w", outPath, err))
            continue
        }
        fmt.Printf("[+] Encrypted: %s → %s\n", path, outPath)
    }
    for _, e := range errors {
        fmt.Fprintf(os.Stderr, "[-] %v\n", e)
    }
    if len(errors) > 0 {
        return fmt.Errorf("%d of %d files failed", len(errors), len(paths))
    }
    return nil
}
```

- [ ] **Step 5: Build CLI**

Run: `go build ./cmd/cli/...`
Expected: builds clean

---

### Task 4: CLI — train mode decrypt

**Files:**
- Modify: `cmd/cli/main.go`

- [ ] **Step 1: Modify runDecrypt for train mode**

Same pattern as encrypt — detect mode, dispatch:

```go
func decryptTrain(paths []string, outputDir string, opts *crypto.DecryptFileOptions) error {
    if outputDir == "" {
        outputDir = "decrypted"
    }
    if err := os.MkdirAll(outputDir, 0755); err != nil {
        return err
    }
    var errors []error
    for _, path := range paths {
        plaintext, header, err := crypto.DecryptFile(path, opts)
        if err != nil {
            errors = append(errors, fmt.Errorf("decrypting %s: %w", path, err))
            continue
        }
        outName := strings.TrimSuffix(filepath.Base(path), ".enc")
        if header.OriginalName != "" {
            outName = header.OriginalName
        }
        outPath := filepath.Join(outputDir, outName)
        if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
            errors = append(errors, fmt.Errorf("writing %s: %w", outPath, err))
            continue
        }
        fmt.Printf("[+] Decrypted: %s → %s\n", path, outPath)
    }
    // ... error summary
}
```

- [ ] **Step 2: Build + verify**

Run: `go build ./cmd/cli/...`
Expected: builds clean

---

### Task 5: CLI — genkey changes (universal, seed-based, extract-public)

**Files:**
- Modify: `cmd/cli/main.go`

- [ ] **Step 1: Update genkey command**

Update `genkeyCmd` RunE:

```go
RunE: func(cmd *cobra.Command, args []string) error {
    // --extract-public takes priority
    if extractPublic {
        if len(args) != 1 {
            return errors.New("usage: kryp genkey --extract-public <private-key-path>")
        }
        kp, err := crypto.ExtractPublicKey(args[0])
        if err != nil {
            return err
        }
        pubPath := args[0] + ".pub"
        if err := os.WriteFile(pubPath, kp.PublicKey, 0644); err != nil {
            return err
        }
        fmt.Printf("[+] Public key extracted: %s\n", pubPath)
        return nil
    }

    // 1 arg = universal key
    if len(args) == 1 {
        key := make([]byte, 64)
        _, err := rand.Read(key)
        if err != nil {
            return err
        }
        return os.WriteFile(args[0], key, 0600)
    }

    // 2 args = algorithm + output
    if len(args) < 2 {
        return errors.New("usage: kryp genkey [algorithm] <output> [--seed-file <path>]")
    }

    algoName := args[0]
    outPath := args[1]

    // --seed-file → deterministic PQC keygen
    if seedFile != "" {
        seed, err := os.ReadFile(seedFile)
        if err != nil {
            return err
        }
        algoID, err := crypto.ParseAlgorithm(algoName)
        if err != nil {
            return err
        }
        kp, err := crypto.GenerateKeyPairFromSeed(algoID, seed)
        if err != nil {
            return err
        }
        return writeKEMKeypair(outPath, kp, algoName)
    }

    // existing behavior (2 args, no seed)
    algoID, err := crypto.ParseAlgorithm(algoName)
    // ... existing switch cases ...
}
```

- [ ] **Step 2: Update genkey usage description**

Replace the existing genkey Long text:

```go
Long: `Generate a random key file or keypair.

Usage:
  kryp genkey <output>                         # 64B universal symmetric key
  kryp genkey <algorithm> <output>             # algorithm-specific key or keypair
  kryp genkey <algorithm> <output> --seed-file <path>  # deterministic PQC keypair from seed
  kryp genkey --extract-public <private-key>   # recover public key from private key

Algorithms: xchacha20-poly1305, chacha20-poly1305, aes-256-gcm, secretbox, ...
For PQC algorithms, generates a keypair (private + .pub).`,
```

- [ ] **Step 3: Build**

Run: `go build ./cmd/cli/...`
Expected: builds clean

---

### Task 6: CLI — --compatible flag on encrypt

**Files:**
- Modify: `cmd/cli/main.go`

- [ ] **Step 1: Register --compatible flag**

In `encryptCmd`:

```go
cmd.Flags().BoolVarP(&compatible, "compatible", "", false, "Compatible mode: no kryp header, raw standard format (interop with OpenSSL etc.)")
```

- [ ] **Step 2: Pass Compatible to EncryptFileOptions**

In `runEncrypt`, add to opts:

```go
encOpts := &crypto.EncryptFileOptions{
    Algorithm:       algoID,
    Passphrase:      []byte(passphrase),
    KeyFile:         keyFile,
    KDFMethod:       kdf,
    UUIDRename:      uuidRename,
    EmbedMetadata:   embedMetadata,
    AgeRecipient:    ageRecipient,
    OriginalPathHint: relPath,
    Compatible:      compatible,
    // ...
}
```

Also add `Compatible` to the manifest encrypt options block if applicable.

- [ ] **Step 3: Build**

Run: `go build ./cmd/cli/...`
Expected: builds clean

---

### Task 7: GUI — multi-file select + train mode

**Files:**
- Modify: `cmd/gui/main.go`

- [ ] **Step 1: Enable multi-select in file dialog**

Change file dialog for encrypt/decrypt to `dialog.NewFileOpen` with multi-select:

```go
// Encrypt button handler:
"Encrypt": func() {
    fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
        // Currently handles single file
        // Change to: use multiple URIs
    }, window)
    fd.Resize(dialogSize)
    // Multi-select not directly supported in Fyne — use multiple dialogs or custom
    // Alternative: add "Add Files" button that accumulates file list
    fd.Show()
},
```

Fyne's `dialog.NewFileOpen` doesn't support native multi-select. Workaround: provide "Add File" button that appends to a list, displayed in a `widget.List` above the file area. Each entry shows filename with a remove button.

- [ ] **Step 2: Display file list UI**

Add a `widget.List` showing selected files. Each item has filename + remove button.

```go
fileList := widget.NewList(
    func() int { return len(selectedFiles) },
    func() (fyne.CanvasObject) {
        return fyne.NewContainerWithLayout(
            layout.NewBorderLayout(nil, nil, nil, removeBtn),
            fileName,
        )
    },
    func(id widget.ListItemID, obj fyne.CanvasObject) {
        // set file name text
    },
)
```

- [ ] **Step 3: Process files in loop**

When "Encrypt" clicked, iterate `selectedFiles`, call `crypto.EncryptFile` for each, update log area.

- [ ] **Step 4: Build**

Run: `go vet ./cmd/gui/...`
Expected: clean or CGO-related warnings only

---

### Task 8: GUI — universal key gen + seed-based PQC keygen + extract public

**Files:**
- Modify: `cmd/gui/main.go`

- [ ] **Step 1: Key gen dialog — make algorithm optional**

In the key generation dialog, make the algorithm select not required. When no algorithm selected, generate 64B universal key.

```go
algoSelect := widget.NewSelect([]string{"", "xchacha20-poly1305", "aes-256-gcm", ...}, nil)
algoSelect.PlaceHolder = "Universal (no algorithm)"
```

- [ ] **Step 2: Add seed file input**

Add a "Seed file" entry field + browse button in the key gen dialog. When filled, uses seed-based deterministic keygen.

- [ ] **Step 3: Add extract public key button**

Add "Extract Public Key" button in key gen dialog. Opens file dialog to select private key file, calls `crypto.ExtractPublicKey`, saves `.pub`.

- [ ] **Step 4: Build**

Run: `go vet ./cmd/gui/...`
Expected: clean or CGO-related warnings only

---

### Task 9: GUI — compatible checkbox

**Files:**
- Modify: `cmd/gui/main.go`

- [ ] **Step 1: Add "Compatible mode" checkbox**

In encrypt dialog, add a `widget.Check` labeled "Compatible mode (no header)". When checked, disable UUID rename and metadata checkboxes.

```go
compatCheck := widget.NewCheck("Compatible mode (no header)", func(checked bool) {
    uuidCheck.Disable()
    metadataCheck.Disable()
})
```

- [ ] **Step 2: Pass compatible flag to EncryptFileOptions**

In the encrypt handler, set `opts.Compatible = compatCheck.Checked`.

- [ ] **Step 3: Build**

Run: `go vet ./cmd/gui/...`
Expected: clean or CGO-related warnings only

---

### Task 10: Documentation — raw payload format

**Files:**
- Modify: `docs/ALGORITHMS.md`

- [ ] **Step 1: Add raw payload format section**

After the KDF section, add a "Raw Payload Format" section documenting:

1. The kryp header structure (4B ENCR + 1B version + 4B bodyLen + body)
2. How to strip the header (3 methods: kryp inspect, python3, dd)
3. Raw ciphertext format table per algorithm (nonce + ciphertext + tag layout)
4. OpenSSL/interop examples for compatible mode

- [ ] **Step 2: Verify markdown renders**

Read the file to check formatting.

---

### Task 11: Tests

**Files:**
- Modify: `test/e2e_test.go`
- Modify: `internal/crypto/registry_test.go` (or add test file)

- [ ] **Step 1: Unit test — ExtractPublicKey**

```go
func TestExtractPublicKey(t *testing.T) {
    // Generate ML-KEM-768 keypair
    kp, err := GenerateMLKEMKeypair()
    require.NoError(t, err)

    // Write private key to temp file
    tmpDir := t.TempDir()
    privPath := filepath.Join(tmpDir, "mlkem768")
    require.NoError(t, os.WriteFile(privPath, kp.PrivateSeed, 0600))

    // Extract public key
    extracted, err := ExtractPublicKey(privPath)
    require.NoError(t, err)
    require.Equal(t, kp.PublicKey, extracted.PublicKey)
}
```

- [ ] **Step 2: Unit test — GenerateKeyPairFromSeed deterministic**

```go
func TestGenerateKeyPairFromSeed(t *testing.T) {
    seed := make([]byte, 64)
    for i := range seed {
        seed[i] = byte(i)
    }

    kp1, err := GenerateKeyPairFromSeed(AlgoMLKEM768, seed)
    require.NoError(t, err)

    kp2, err := GenerateKeyPairFromSeed(AlgoMLKEM768, seed)
    require.NoError(t, err)

    require.Equal(t, kp1.PrivateSeed, kp2.PrivateSeed, "same seed must produce same keypair")
    require.Equal(t, kp1.PublicKey, kp2.PublicKey, "same seed must produce same public key")
}
```

- [ ] **Step 3: Unit test — encryptCompatible no header**

```go
func TestEncryptCompatible(t *testing.T) {
    key := make([]byte, 32)
    rand.Read(key)
    tmpKey := filepath.Join(t.TempDir(), "key.bin")
    os.WriteFile(tmpKey, key, 0600)

    opts := &EncryptFileOptions{
        Algorithm: AlgoAES256GCM,
        KeyFile:   tmpKey,
        Compatible: true,
    }

    data := []byte("test data")
    result, err := EncryptFileBytes(data, opts)
    require.NoError(t, err)

    // Should NOT start with ENCR
    if len(result) >= 4 && result[0] == 'E' && result[1] == 'N' && result[2] == 'C' && result[3] == 'R' {
        t.Error("compatible output should not have ENCR header")
    }

    // Should be decryptable without header
    nonceSize := 12 // AES-256-GCM
    require.True(t, len(result) > nonceSize)
    nonce := result[:nonceSize]
    ct := result[nonceSize:]
    enc, _ := GetEncryptor(AlgoAES256GCM)
    decrypted, err := enc.Decrypt(ct, key, nonce)
    require.NoError(t, err)
    require.Equal(t, data, decrypted)
}
```

- [ ] **Step 4: E2E — train mode encrypt + decrypt 3 files**

```go
func TestTrainModeE2E(t *testing.T) {
    tmpDir := t.TempDir()
    // Create 3 test files
    files := []string{"a.txt", "b.txt", "c.txt"}
    for _, f := range files {
        os.WriteFile(filepath.Join(tmpDir, f), []byte("content-"+f), 0644)
    }
    keyFile := filepath.Join(tmpDir, "key.bin")
    key := make([]byte, 32)
    rand.Read(key)
    os.WriteFile(keyFile, key, 0600)

    // Train encrypt
    encDir := filepath.Join(tmpDir, "enc")
    cmd := exec.Command(krypBin, "encrypt",
        "-s", filepath.Join(tmpDir, "a.txt"),
        filepath.Join(tmpDir, "b.txt"),
        filepath.Join(tmpDir, "c.txt"),
        "-o", encDir,
        "--key-file", keyFile,
    )
    out, err := cmd.CombinedOutput()
    require.NoError(t, err, "train encrypt failed: %s", out)

    // Verify 3 .enc files
    for _, f := range files {
        _, err := os.Stat(filepath.Join(encDir, f+".enc"))
        require.NoError(t, err, "missing encrypted file %s", f+".enc")
    }

    // Train decrypt
    decDir := filepath.Join(tmpDir, "dec")
    cmd = exec.Command(krypBin, "decrypt",
        "-s", filepath.Join(encDir, "a.txt.enc"),
        filepath.Join(encDir, "b.txt.enc"),
        filepath.Join(encDir, "c.txt.enc"),
        "-o", decDir,
        "--key-file", keyFile,
    )
    out, err = cmd.CombinedOutput()
    require.NoError(t, err, "train decrypt failed: %s", out)

    // Verify decrypted content
    for _, f := range files {
        data, err := os.ReadFile(filepath.Join(decDir, f))
        require.NoError(t, err)
        require.Equal(t, "content-"+f, string(data))
    }
}
```

- [ ] **Step 5: E2E — --files-from**

```go
func TestFilesFrom(t *testing.T) {
    tmpDir := t.TempDir()
    files := []string{"x.txt", "y.txt"}
    for _, f := range files {
        os.WriteFile(filepath.Join(tmpDir, f), []byte(f), 0644)
    }
    // Create file list
    listPath := filepath.Join(tmpDir, "list.txt")
    listContent := strings.Join([]string{
        filepath.Join(tmpDir, "x.txt"),
        "# this is a comment",
        "",
        filepath.Join(tmpDir, "y.txt"),
    }, "\n")
    os.WriteFile(listPath, []byte(listContent), 0644)

    keyFile := filepath.Join(tmpDir, "key.bin")
    key := make([]byte, 32)
    rand.Read(key)
    os.WriteFile(keyFile, key, 0600)

    cmd := exec.Command(krypBin, "encrypt",
        "--files-from", listPath,
        "-o", filepath.Join(tmpDir, "enc"),
        "--key-file", keyFile,
    )
    out, err := cmd.CombinedOutput()
    require.NoError(t, err, "--files-from encrypt failed: %s", out)
}
```

- [ ] **Step 6: E2E — universal key + cross-algo encrypt**

```go
func TestUniversalKeyCrossAlgo(t *testing.T) {
    tmpDir := t.TempDir()
    data := []byte("secret data")
    src := filepath.Join(tmpDir, "data.txt")
    os.WriteFile(src, data, 0644)

    // Generate universal key (64B)
    uniKey := filepath.Join(tmpDir, "uni.bin")
    cmd := exec.Command(krypBin, "genkey", uniKey)
    out, err := cmd.CombinedOutput()
    require.NoError(t, err, "genkey failed: %s", out)

    // Encrypt with aes-256-gcm (32B algo)
    encDir := filepath.Join(tmpDir, "enc")
    cmd = exec.Command(krypBin, "encrypt",
        "-s", src,
        "-o", encDir,
        "--algorithm", "aes-256-gcm",
        "--key-file", uniKey,
    )
    out, err = cmd.CombinedOutput()
    require.NoError(t, err, "encrypt with uni key failed: %s", out)
}
```

- [ ] **Step 7: Run all tests**

Run: `go test -count=1 -timeout 120s ./internal/... && go test -count=1 -timeout 600s ./test/...`
Expected: all pass

---

### Task 12: Verify everything

- [ ] **Step 1: go vet**

Run: `go vet ./...`
Expected: clean

- [ ] **Step 2: Build CLI**

Run: `go build ./cmd/cli/...`
Expected: clean

- [ ] **Step 3: Run internal tests**

Run: `go test -count=1 -timeout 120s ./internal/...`
Expected: all pass

- [ ] **Step 4: Run E2E tests**

Run: `go test -count=1 -timeout 600s ./test/...`
Expected: all pass
