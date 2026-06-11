package core

type AlgorithmID byte

const (
	AlgoNone              AlgorithmID = 0
	AlgoXChaCha20Poly1305 AlgorithmID = 1
	AlgoChaCha20Poly1305  AlgorithmID = 2
	AlgoAES256GCM         AlgorithmID = 3
	AlgoSecretBox         AlgorithmID = 4
	AlgoAES256CTRHMAC     AlgorithmID = 5
	AlgoAge               AlgorithmID = 6
	AlgoMLKEM768          AlgorithmID = 7
	AlgoMLKEM1024         AlgorithmID = 8
	AlgoHybridXWing       AlgorithmID = 9
	AlgoHPKE              AlgorithmID = 10
	AlgoASCON128          AlgorithmID = 11
)

func (a AlgorithmID) String() string {
	switch a {
	case AlgoXChaCha20Poly1305:
		return "XChaCha20-Poly1305"
	case AlgoChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	case AlgoAES256GCM:
		return "AES-256-GCM"
	case AlgoSecretBox:
		return "NaCl SecretBox (XSalsa20-Poly1305)"
	case AlgoAES256CTRHMAC:
		return "AES-256-CTR+HMAC-SHA256"
	case AlgoAge:
		return "age (X25519+ChaCha20-Poly1305)"
	case AlgoMLKEM768:
		return "ML-KEM-768 (FIPS 203)"
	case AlgoMLKEM1024:
		return "ML-KEM-1024 (FIPS 203)"
	case AlgoHybridXWing:
		return "Hybrid X-Wing (X25519+ML-KEM-768)"
	case AlgoHPKE:
		return "HPKE (X25519+HKDF-SHA256+ChaCha20-Poly1305)"
	case AlgoASCON128:
		return "ASCON-128 (NIST Lightweight)"
	default:
		return "unknown"
	}
}

type KDFMethod byte

const (
	KDFNone     KDFMethod = 0
	KDFArgon2id KDFMethod = 1
	KDFScrypt   KDFMethod = 2
	KDFPBKDF2   KDFMethod = 3
)

func (k KDFMethod) String() string {
	switch k {
	case KDFArgon2id:
		return "Argon2id"
	case KDFScrypt:
		return "scrypt"
	case KDFPBKDF2:
		return "PBKDF2"
	case KDFNone:
		return "none"
	default:
		return "unknown"
	}
}

type EncryptionResult struct {
	Algorithm  AlgorithmID
	Ciphertext []byte
	Nonce      []byte
}

type Encryptor interface {
	ID() AlgorithmID
	Encrypt(plaintext []byte, key []byte) (*EncryptionResult, error)
	Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error)
	NonceSize() int
	KeySize() int
}
