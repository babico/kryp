# Encryption Algorithms & Usage

## Algorithm Types

### Symmetric Ciphers

| Algorithm | Key Size | Nonce | Auth Tag | Best For |
| --------- | -------- | ----- | -------- | -------- |
| **XChaCha20-Poly1305** | 32 B | 24 B | 16 B | General purpose (default) |
| **ChaCha20-Poly1305** | 32 B | 12 B | 16 B | Compatible with existing ChaCha20 systems |
| **AES-256-GCM** | 32 B | 12 B | 16 B | Hardware AES acceleration, compliance |
| **SecretBox** (XSalsa20-Poly1305) | 32 B | 24 B | 16 B | NaCl/libsodium compatibility |
| **AES-256-CTR+HMAC** | 64 B | 16 B | 32 B | Encrypt-then-MAC, FIPS-friendly |

### Lightweight / NIST-LWC

| Algorithm | Key Size | Nonce | Tag | Best For |
| --------- | -------- | ----- | --- | -------- |
| **ASCON-128** | 16 B | 16 B | 16 B | Lightweight, NIST standard, embedded |
| **AEGIS-128L** | 16 B | 16 B | 16 B | High-speed AES-NI, NIST LWC finalist |
| **AEGIS-256** | 32 B | 32 B | 16 B | High-speed AES-NI, 256-bit security |
| **Xoodyak** | 16 B | 16 B | 16 B | NIST LWC finalist, lightweight yet fast |

### CAESAR Finalist

| Algorithm | Key Size | Nonce | Tag | Best For |
| --------- | -------- | ----- | --- | -------- |
| **Deoxys-II-256-128** | 32 B | 15 B | 16 B | CAESAR finalist, AES-NI accelerated |

### Nonce-Misuse Resistant

| Algorithm | Key Size | Nonce | Tag | Best For |
| --------- | -------- | ----- | --- | -------- |
| **AES-256-GCM-SIV** | 32 B | 12 B | 16 B | Nonce-misuse resistance, RFC 8452 |
| **AES-256-SIV** | 64 B | 16 B | 16 B | RFC 5297, deterministic/nonce-misuse resistant |

### Asymmetric (Public-Key)

| Algorithm | Key Sizes | Type | Best For |
| --------- | --------- | ---- | -------- |
| **Age** | Recipient/Identity | X25519 | Modern asymmetric, SSH-like keys |
| **ML-KEM-768** | Pub 1184 B, Priv 64 B | FIPS 203 PQ | Post-quantum security |
| **ML-KEM-1024** | Pub 1568 B, Priv 64 B | FIPS 203 PQ | Highest PQ security |
| **X-Wing** | Pub 1216 B, Priv 32 B | X25519 + ML-KEM-768 | Hybrid defense-in-depth |
| **HPKE** (RFC 9180) | Varies | KEM + KDF + AEAD | Standards-based hybrid |
| **HQC-128** | Pub 2241 B, Priv 2321 B | FIPS 207 PQ | Code-based PQ backup to ML-KEM |
| **FrodoKEM-640-SHAKE** | Pub 9616 B, Priv 19888 B | NIST PQC Round 3 | Conservative lattice-based PQ, SHAKE-128 |

## Usage Examples

### Basic symmetric encryption (default: XChaCha20 + Argon2id)

```bash
# Single file
kryp encrypt -s secret.txt -o secret.txt.enc --passphrase "my password"

# Directory
kryp encrypt -s ./docs/ -o ./encrypted/ --passphrase "my password"

# Decrypt
kryp decrypt -s secret.txt.enc -o secret.txt --passphrase "my password"
kryp decrypt -s ./encrypted/ -o ./decrypted/ --passphrase "my password"
```

### With key file

```bash
kryp genkey xchacha20-poly1305 key.bin
kryp encrypt -s secret.txt -o secret.txt.enc --key-file key.bin
kryp decrypt -s secret.txt.enc -o secret.txt --key-file key.bin
```

### UUID rename (organize encrypted files by UUID, mapping stored in manifest)

```bash
kryp encrypt -s ./docs/ -o ./encrypted/ --uuid-rename --passphrase "pw"
# Files become: <uuid>.enc
# Mapping in: manifest.json.enc
kryp list ./encrypted/
kryp decrypt -s ./encrypted/ -o ./decrypted/ --passphrase "pw"
```

### Metadata embedding (recover original name without manifest)

```bash
kryp encrypt -s secret.txt -o secret.txt.enc --embed-metadata --passphrase "pw"
# Header stores original filename/path
kryp inspect secret.txt.enc
# Shows: Orig Name: secret.txt
```

### Age asymmetric encryption

```bash
# Generate identity (private) + recipient (public)
kryp genkey age keys/
# Encrypt with recipient key
kryp encrypt -s secret.txt -o secret.txt.enc --algorithm age --age-recipient "age1..."
# Decrypt with identity (key-file)
kryp decrypt -s secret.txt.enc -o secret.txt --algorithm age --key-file keys/age.key
```

### Post-quantum (ML-KEM / X-Wing / HQC)

```bash
# Generate keypair (public for encrypt, private seed for decrypt)
kryp genkey ml-kem-768 keys/
kryp encrypt -s secret.txt -o secret.txt.enc --algorithm ml-kem-768 --key-file keys/mlkem768.pub
kryp decrypt -s secret.txt.enc -o secret.txt --algorithm ml-kem-768 --key-file keys/mlkem768

# HQC-128 (code-based PQ backup)
kryp genkey hqc-128 keys/
kryp encrypt -s secret.txt -o secret.txt.enc --algorithm hqc-128 --key-file keys/hqc.pub
kryp decrypt -s secret.txt.enc -o secret.txt --algorithm hqc-128 --key-file keys/hqc
```

### AEGIS (high-speed AES-NI)

```bash
kryp encrypt -s secret.txt -o secret.txt.enc --algorithm aegis-128l --passphrase "pw"
kryp encrypt -s secret.txt -o secret.txt.enc --algorithm aegis-256 --passphrase "pw"
```

### AES-256-GCM-SIV (nonce-misuse resistant)

```bash
kryp genkey aes-256-gcm-siv key.bin
kryp encrypt -s secret.txt -o secret.txt.enc --algorithm aes-256-gcm-siv --key-file key.bin
```

### Xoodyak (NIST LWC finalist)

```bash
kryp encrypt -s secret.txt -o secret.txt.enc --algorithm xoodyak --passphrase "pw"
```

### Deoxys-II-256-128 (CAESAR finalist)

```bash
kryp encrypt -s secret.txt -o secret.txt.enc --algorithm deoxys-ii --passphrase "pw"
```

### AES-256-SIV (nonce-misuse resistant, RFC 5297)

```bash
kryp genkey aes-256-siv key.bin
kryp encrypt -s secret.txt -o secret.txt.enc --algorithm aes-256-siv --key-file key.bin
```

### FrodoKEM-640-SHAKE (conservative lattice PQC)

```bash
kryp genkey frodokem-640-shake keys/
kryp encrypt -s secret.txt -o secret.txt.enc --algorithm frodokem-640-shake --key-file keys/frodokem640.pub
kryp decrypt -s secret.txt.enc -o secret.txt --algorithm frodokem-640-shake --key-file keys/frodokem640
```

### KDF methods + custom parameters

```bash
kryp encrypt -s secret.txt -o secret.txt.enc --passphrase "pw" --kdf argon2id
kryp encrypt -s secret.txt -o secret.txt.enc --passphrase "pw" --kdf scrypt
kryp encrypt -s secret.txt -o secret.txt.enc --passphrase "pw" --kdf pbkdf2
# "none" for already-random keys or algorithm with built-in KDF
kryp encrypt -s secret.txt -o secret.txt.enc --key-file key.bin --kdf none

# Custom KDF parameters (defaults used if not specified)
kryp encrypt -s secret.txt -o secret.txt.enc --passphrase "pw" --argon2-time 3 --argon2-memory 131072 --argon2-threads 4
kryp encrypt -s secret.txt -o secret.txt.enc --passphrase "pw" --kdf scrypt --scrypt-n 65536 --scrypt-r 8 --scrypt-p 1
kryp encrypt -s secret.txt -o secret.txt.enc --passphrase "pw" --kdf pbkdf2 --pbkdf2-iter 1000000
```

### Train mode (multi-file)

```bash
# Encrypt multiple files at once
kryp encrypt -s a.txt b.jpg c.pdf -o encrypted/ --passphrase "pw"

# With file list
kryp encrypt --files-from filelist.txt -o encrypted/ --key-file key.bin

# Decrypt multiple files
kryp decrypt -s a.txt.enc b.jpg.enc -o decrypted/ --key-file key.bin

# File list format (one path per line, # comments, blank lines skipped)
echo -e "a.txt\nb.txt\n# skip this comment\n\nc.txt" > list.txt
```

### Universal key (cross-algorithm)

```bash
# Generate a 64B universal key (works with any symmetric algorithm)
kryp genkey universal.bin

# Use with different algorithms — key is sliced to fit
kryp encrypt -s file.txt --algorithm aes-256-gcm --key-file universal.bin
kryp encrypt -s file.txt --algorithm xchacha20-poly1305 --key-file universal.bin

# Deterministic PQC keypair from seed
kryp genkey ml-kem-768 keys/ --seed-file universal.bin
kryp genkey frodokem-640-shake keys/ --seed-file universal.bin

# Extract public key from private key
kryp genkey --extract-public keys/mlkem768
# Creates: keys/mlkem768.pub
```

### Compatible mode (interop with other tools)

```bash
# Encrypt without kryp header — raw standard format
kryp encrypt -s file.txt --algorithm aes-256-gcm --key-file key.bin --compatible -o file.enc
# Output: [12B nonce][ciphertext+tag] — decryptable with OpenSSL:
# openssl enc -d -aes-256-gcm -K <hex(key)> -iv <hex(nonce)> -in file.enc

# SecretBox compatible with libsodium
kryp encrypt -s file.txt --algorithm secretbox --passphrase "pw" --compatible -o file.enc
```

### Raw payload format (for interop without --compatible)

Kryp wraps all encrypted data in a header. To extract the raw ciphertext:

```plaintext
Offset  Size  Field
0       4     Magic bytes "ENCR"
4       1     Header version (1)
5       4     Body length (uint32 BE)
9       N     Header body
9+N     -     Raw ciphertext
```

Stripping the header:

```bash
# Using kryp inspect to get header size
kryp inspect file.enc | grep "Header size"
dd if=file.enc bs=1 skip=<header_size> of=raw.bin

# Using Python
python3 -c "
import sys
with open(sys.argv[1], 'rb') as f:
    d = f.read()
    sys.stdout.buffer.write(d[9+int.from_bytes(d[5:9],'big'):])
" file.enc > raw.bin

# Using PowerShell
$d = Get-Content file.enc -AsByteStream -Raw
$bl = [System.BitConverter]::ToUInt32($d[5..8], 0) -as [bigendian]
[System.IO.File]::WriteAllBytes('raw.bin', $d[(9+$bl)..$($d.Length-1)])
```

Raw format per algorithm (after stripping header):

| Algorithm | Nonce | Payload |
| --------- | ----- | ------- |
| AES-256-GCM | 12B | ciphertext + 16B tag |
| ChaCha20-Poly1305 | 12B | ciphertext + 16B tag |
| XChaCha20-Poly1305 | 24B | ciphertext + 16B tag |
| SecretBox | 24B | ciphertext + 16B tag |
| AES-256-CTR+HMAC | 16B IV | ciphertext + 32B HMAC |
| ASCON-128 / Xoodyak | 16B | ciphertext + 16B tag |
| AEGIS-128L | 16B | ciphertext + 16B tag |
| AEGIS-256 | 32B | ciphertext + 16B tag |
| AES-256-GCM-SIV | 12B | ciphertext + 16B tag |
| AES-256-SIV | 16B | ciphertext + 16B tag |
| Deoxys-II-256-128 | 15B | ciphertext + 16B tag |

### Pipe mode (stdin/stdout)

```bash
cat secret.txt | kryp encrypt --algorithm xchacha20-poly1305 --passphrase "pw" > secret.txt.enc
cat secret.txt.enc | kryp decrypt --passphrase "pw" > secret.txt
```

## Algorithm Aliases

| Use | Aliases |
| --- | ------- |
| xchacha20 | `xchacha20`, `xchacha20-poly1305`, `chacha20-ietf-poly1305` |
| chacha20 | `chacha20`, `chacha20-poly1305` |
| aes-gcm | `aes-gcm`, `aes-256-gcm`, `aes256-gcm` |
| secretbox | `secretbox`, `xsalsa20-poly1305`, `nacl` |
| aes-ctr-hmac | `aes-ctr-hmac`, `aes-256-ctr-hmac`, `aes256-ctr-hmac` |
| ascon | `ascon`, `ascon-128`, `nist-lwc` |
| aegis-128l | `aegis-128l`, `aegis128l` |
| aegis-256 | `aegis-256`, `aegis256` |
| aes-gcm-siv | `aes-256-gcm-siv`, `aes-gcm-siv`, `gcm-siv` |
| age | `age`, `age-encryption` |
| ml-kem-768 | `ml-kem-768`, `kyber`, `pqc`, `post-quantum`, `kem` |
| ml-kem-1024 | `ml-kem-1024`, `kyber-1024`, `pqc-1024` |
| x-wing | `x-wing`, `xwing`, `hybrid`, `kem-hybrid` |
| hpke | `hpke`, `hpke-base`, `rfc-9180` |
| hqc-128 | `hqc-128`, `hqc128`, `hqc` |
| xoodyak | `xoodyak` |
| deoxys-ii | `deoxys-ii`, `deoxysii` |
| aes-256-siv | `aes-256-siv`, `aes-siv`, `siv` |
| frodokem-640-shake | `frodokem-640-shake`, `frodokem640`, `frodo` |

## Config File

See `docs/examples/basic.yaml` and `docs/examples/advanced.yaml`.

```yaml
encryption:
  algorithm: xchacha20-poly1305
  kdf_method: argon2id
  passphrase: ""
  key_file: ""
  uuid_rename: false
  embed_metadata: false
  # Optional KDF parameter overrides (omit for defaults)
  # argon2_time: 3
  # argon2_memory: 65536
  # argon2_threads: 4
  # scrypt_n: 32768
  # scrypt_r: 8
  # scrypt_p: 1
  # pbkdf2_iter: 600000

directories:
  source: test/original
  output: test/encrypted
  decrypted: test/decrypted

database:
  encrypt: true
```

Environment variable overrides: `ENCRYPT_CLI_PASSPHRASE`, `ENCRYPT_CLI_KEY_FILE`.
