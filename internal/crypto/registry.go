package crypto

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"filippo.io/mlkem768/xwing"
	"github.com/cloudflare/circl/hpke"

	"github.com/babico/kryp/internal/crypto/asymmetric"
	"github.com/babico/kryp/internal/crypto/pqc"
	"github.com/babico/kryp/internal/crypto/symmetric"
)

var encryptors = map[AlgorithmID]Encryptor{
	AlgoXChaCha20Poly1305: &symmetric.XChaCha20{},
	AlgoChaCha20Poly1305:  &symmetric.ChaCha20Poly1305{},
	AlgoAES256GCM:         &symmetric.AES256GCM{},
	AlgoSecretBox:         &symmetric.SecretBox{},
	AlgoAES256CTRHMAC:     &symmetric.AES256CTRHMAC{},
	AlgoAge:               &asymmetric.AgeEncryptor{},
	AlgoMLKEM768:          &pqc.MLKEM768{},
	AlgoMLKEM1024:         &pqc.MLKEM1024{},
	AlgoHybridXWing:       &pqc.HybridXWing{},
	AlgoHPKE:              &asymmetric.HPKEEncryptor{},
	AlgoASCON128:          &symmetric.ASCON128{},
}

func GetEncryptor(id AlgorithmID) (Encryptor, error) {
	e, ok := encryptors[id]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm: %d", id)
	}
	return e, nil
}

func ListAlgorithms() []AlgorithmID {
	ids := make([]AlgorithmID, 0, len(encryptors))
	for id := range encryptors {
		ids = append(ids, id)
	}
	return ids
}

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
}

type DecryptFileOptions struct {
	Passphrase []byte
	KeyFile    string
}

func loadKey(keyFile string, keyLen int) ([]byte, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	if len(data) < keyLen {
		return nil, fmt.Errorf("key file too short: need %d bytes, got %d", keyLen, len(data))
	}
	return data[:keyLen], nil
}

func resolveDecryptKey(passphrase []byte, keyFile string, kdfMethod KDFMethod, salt []byte, kdfParams []byte, expectedKeyLen int) ([]byte, error) {
	if len(passphrase) > 0 && kdfMethod != KDFNone {
		return DeriveKey(passphrase, kdfMethod, salt, kdfParams, expectedKeyLen)
	}
	if keyFile != "" {
		return loadKey(keyFile, expectedKeyLen)
	}
	return nil, errors.New("no passphrase or key file provided")
}

func readFullHeader(path string) (*Header, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	header, err := DecodeHeader(data)
	if err != nil {
		return nil, nil, err
	}
	headerSize := len(header.Encode())
	return header, data[headerSize:], nil
}

func deriveKeyFromOpts(opts *EncryptFileOptions, expectedKeyLen int) (key []byte, kdfMethod KDFMethod, kdfSalt, kdfParams []byte, err error) {
	if len(opts.Passphrase) > 0 {
		kdfMethod = opts.KDFMethod
		kdfSalt, err = GenerateSalt(DefaultSaltSize)
		if err != nil {
			return
		}
		switch kdfMethod {
		case KDFArgon2id:
			kdfParams = EncodeArgon2Params(DefaultArgon2Time, DefaultArgon2Memory, DefaultArgon2Threads)
		case KDFScrypt:
			kdfParams = EncodeScryptParams(DefaultScryptN, DefaultScryptR, DefaultScryptP)
		case KDFPBKDF2:
			kdfParams = EncodePBKDF2Params(DefaultPBKDF2Iter)
		default:
			err = fmt.Errorf("unsupported KDF: %d", kdfMethod)
			return
		}
		key, err = DeriveKey(opts.Passphrase, kdfMethod, kdfSalt, kdfParams, expectedKeyLen)
		return
	}

	if opts.KeyFile != "" {
		kdfMethod = KDFNone
		key, err = loadKey(opts.KeyFile, expectedKeyLen)
		return
	}

	kdfMethod = KDFNone
	key = make([]byte, expectedKeyLen)
	_, err = rand.Read(key)
	return
}

func EncryptFile(filePath string, opts *EncryptFileOptions) ([]byte, error) {
	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	effectiveOpts := *opts
	if opts.EmbedMetadata {
		if effectiveOpts.OriginalNameHint == "" {
			effectiveOpts.OriginalNameHint = filepath.Base(filePath)
		}
		if effectiveOpts.OriginalPathHint == "" {
			effectiveOpts.OriginalPathHint = filePath
		}
	}

	return encryptFileBytes(plaintext, &effectiveOpts)
}

func EncryptFileAge(filePath string, opts *EncryptFileOptions) ([]byte, error) {
	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	effectiveOpts := *opts
	effectiveOpts.Algorithm = AlgoAge
	if opts.EmbedMetadata {
		effectiveOpts.OriginalNameHint = filepath.Base(filePath)
		effectiveOpts.OriginalPathHint = filePath
	}
	return encryptAgeBytes(plaintext, &effectiveOpts)
}

func resolveDecryptKeyForAlgo(algo AlgorithmID, opts *DecryptFileOptions, header *Header, expectedKeyLen int) ([]byte, error) {
	switch algo {
	case AlgoAge:
		if opts.KeyFile == "" {
			return nil, errors.New("age decryption requires an identity key file")
		}
		ageData, err := os.ReadFile(opts.KeyFile)
		if err != nil {
			return nil, err
		}
		return bytes.TrimSpace(ageData), nil
	case AlgoMLKEM768, AlgoMLKEM1024:
		if opts.KeyFile == "" {
			return nil, fmt.Errorf("%s decryption requires a decapsulation key file", algo)
		}
		privKey, err := os.ReadFile(opts.KeyFile)
		if err != nil {
			return nil, err
		}
		if len(privKey) != 64 {
			return nil, fmt.Errorf("%s decapsulation key must be 64 bytes, got %d", algo, len(privKey))
		}
		return privKey, nil
	case AlgoHybridXWing:
		if opts.KeyFile == "" {
			return nil, errors.New("X-Wing decryption requires a decapsulation key file")
		}
		privKey, err := os.ReadFile(opts.KeyFile)
		if err != nil {
			return nil, err
		}
		if len(privKey) != 32 {
			return nil, fmt.Errorf("X-Wing decapsulation key must be 32 bytes, got %d", len(privKey))
		}
		return privKey, nil
	case AlgoHPKE:
		if opts.KeyFile == "" {
			return nil, errors.New("HPKE decryption requires a private key file")
		}
		privKey, err := os.ReadFile(opts.KeyFile)
		if err != nil {
			return nil, err
		}
		if len(privKey) != 32 {
			return nil, fmt.Errorf("HPKE private key must be 32 bytes, got %d", len(privKey))
		}
		return privKey, nil
	default:
		return resolveDecryptKey(opts.Passphrase, opts.KeyFile, header.KDFMethod, header.KDFSalt, header.KDFParams, expectedKeyLen)
	}
}

func DecryptFile(filePath string, opts *DecryptFileOptions) ([]byte, *Header, error) {
	header, ciphertext, err := readFullHeader(filePath)
	if err != nil {
		return nil, nil, err
	}

	encryptor, err := GetEncryptor(header.Algorithm)
	if err != nil {
		return nil, nil, err
	}

	key, err := resolveDecryptKeyForAlgo(header.Algorithm, opts, header, encryptor.KeySize())
	if err != nil {
		return nil, nil, err
	}

	plaintext, err := encryptor.Decrypt(ciphertext, key, header.Nonce)
	if err != nil {
		return nil, nil, err
	}
	return plaintext, header, nil
}

func DetectAlgorithm(filePath string) (AlgorithmID, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, err
	}
	header, err := DecodeHeader(data)
	if err != nil {
		return 0, err
	}
	return header.Algorithm, nil
}

func encryptWithKey(data []byte, algo AlgorithmID, key []byte, kdfMethod KDFMethod, kdfSalt, kdfParams []byte, encryptor Encryptor, origName, origPath string) ([]byte, error) {
	result, err := encryptor.Encrypt(data, key)
	if err != nil {
		return nil, err
	}

	header := &Header{
		Version:      1,
		Algorithm:    algo,
		KDFMethod:    kdfMethod,
		KDFSalt:      kdfSalt,
		KDFParams:    kdfParams,
		Nonce:        result.Nonce,
		OriginalName: origName,
		OriginalPath: origPath,
	}

	headerBytes := header.Encode()
	return append(headerBytes, result.Ciphertext...), nil
}

func EncryptFileBytes(data []byte, opts *EncryptFileOptions) ([]byte, error) {
	return encryptFileBytes(data, opts)
}

func encryptFileBytes(data []byte, opts *EncryptFileOptions) ([]byte, error) {
	if opts.Algorithm == AlgoAge {
		return encryptAgeBytes(data, opts)
	}

	if opts.Algorithm == AlgoMLKEM768 || opts.Algorithm == AlgoMLKEM1024 || opts.Algorithm == AlgoHybridXWing || opts.Algorithm == AlgoHPKE {
		return encryptKEMBytes(data, opts)
	}

	encryptor, err := GetEncryptor(opts.Algorithm)
	if err != nil {
		return nil, err
	}

	key, kdfMethod, kdfSalt, kdfParams, err := deriveKeyFromOpts(opts, encryptor.KeySize())
	if err != nil {
		return nil, err
	}

	var origName, origPath string
	if opts.EmbedMetadata {
		origName = opts.OriginalNameHint
		origPath = opts.OriginalPathHint
	}

	return encryptWithKey(data, opts.Algorithm, key, kdfMethod, kdfSalt, kdfParams, encryptor, origName, origPath)
}

func encryptKEMBytes(data []byte, opts *EncryptFileOptions) ([]byte, error) {
	if opts.KeyFile == "" {
		return nil, fmt.Errorf("%s encryption requires a public key file", opts.Algorithm)
	}

	pubKey, err := os.ReadFile(opts.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("reading %s public key: %w", opts.Algorithm, err)
	}

	enc, err := GetEncryptor(opts.Algorithm)
	if err != nil {
		return nil, err
	}

	result, err := enc.Encrypt(data, pubKey)
	if err != nil {
		return nil, err
	}

	var origName, origPath string
	if opts.EmbedMetadata {
		origName = opts.OriginalNameHint
		origPath = opts.OriginalPathHint
	}

	header := &Header{
		Version:      1,
		Algorithm:    opts.Algorithm,
		KDFMethod:    KDFNone,
		Nonce:        result.Nonce,
		OriginalName: origName,
		OriginalPath: origPath,
	}

	headerBytes := header.Encode()
	return append(headerBytes, result.Ciphertext...), nil
}

func encryptAgeBytes(data []byte, opts *EncryptFileOptions) ([]byte, error) {
	if opts.AgeRecipient == "" {
		return nil, errors.New("age encryption requires a recipient (use --age-recipient)")
	}

	recipient, err := age.ParseX25519Recipient(opts.AgeRecipient)
	if err != nil {
		return nil, fmt.Errorf("parsing age recipient: %w", err)
	}

	buf := new(bytes.Buffer)
	w, err := age.Encrypt(buf, recipient)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(data)
	if err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}

	var origName, origPath string
	if opts.EmbedMetadata {
		origName = opts.OriginalNameHint
		origPath = opts.OriginalPathHint
	}

	header := &Header{
		Version:      1,
		Algorithm:    AlgoAge,
		KDFMethod:    KDFNone,
		OriginalName: origName,
		OriginalPath: origPath,
	}
	headerBytes := header.Encode()
	return append(headerBytes, buf.Bytes()...), nil
}

func DecryptFileBytes(data []byte, opts *DecryptFileOptions) ([]byte, *Header, error) {
	header, err := DecodeHeader(data)
	if err != nil {
		return nil, nil, err
	}
	hdrSize := len(header.Encode())
	ciphertext := data[hdrSize:]

	encryptor, err := GetEncryptor(header.Algorithm)
	if err != nil {
		return nil, nil, err
	}

	key, err := resolveDecryptKeyForAlgo(header.Algorithm, opts, header, encryptor.KeySize())
	if err != nil {
		return nil, nil, err
	}

	plaintext, err := encryptor.Decrypt(ciphertext, key, header.Nonce)
	if err != nil {
		return nil, nil, err
	}
	return plaintext, header, nil
}

func GenerateKey(algorithm AlgorithmID) ([]byte, error) {
	encryptor, err := GetEncryptor(algorithm)
	if err != nil {
		return nil, err
	}
	key := make([]byte, encryptor.KeySize())
	_, err = rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

type KEMKeypair struct {
	Algorithm  AlgorithmID
	PrivateSeed []byte
	PublicKey   []byte
}

func GenerateMLKEMKeypair() (*KEMKeypair, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &KEMKeypair{
		Algorithm:   AlgoMLKEM768,
		PrivateSeed: dk.Bytes(),
		PublicKey:   dk.EncapsulationKey().Bytes(),
	}, nil
}

func GenerateMLKEM1024Keypair() (*KEMKeypair, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}
	return &KEMKeypair{
		Algorithm:   AlgoMLKEM1024,
		PrivateSeed: dk.Bytes(),
		PublicKey:   dk.EncapsulationKey().Bytes(),
	}, nil
}

func GenerateXWingKeypair() (*KEMKeypair, error) {
	dk, err := xwing.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &KEMKeypair{
		Algorithm:   AlgoHybridXWing,
		PrivateSeed: dk.Bytes(),
		PublicKey:   dk.EncapsulationKey(),
	}, nil
}

func GenerateHPKEKeypair() (*KEMKeypair, error) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	kemID, _, _ := suite.Params()
	scheme := kemID.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	privBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	pubBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &KEMKeypair{
		Algorithm:   AlgoHPKE,
		PrivateSeed: privBytes,
		PublicKey:   pubBytes,
	}, nil
}
