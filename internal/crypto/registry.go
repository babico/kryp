package crypto

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

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
	AlgoAEGIS128L:         &symmetric.AEGIS128L{},
	AlgoAEGIS256:          &symmetric.AEGIS256{},
	AlgoAES256GCMSIV:      &symmetric.AES256GCMSIV{},
	AlgoHQC128:            &pqc.HQC128{},
	AlgoXoodyak:           &symmetric.Xoodyak{},
	AlgoDeoxysII:          &symmetric.DeoxysII{},
	AlgoAES256SIV:         &symmetric.AES256SIV{},
	AlgoFrodo640SHAKE:     &pqc.Frodo640SHAKE{},
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
	Algorithm        AlgorithmID
	Passphrase       []byte
	KeyFile          string
	KDFMethod        KDFMethod
	UUIDRename       bool
	EmbedMetadata    bool
	Compatible       bool
	AgeRecipient     string
	OriginalNameHint string
	OriginalPathHint string
	Argon2Time       uint32
	Argon2Memory     uint32
	Argon2Threads    uint8
	ScryptN          uint32
	ScryptR          uint32
	ScryptP          uint32
	PBKDF2Iter       uint32
}

type DecryptFileOptions struct {
	Passphrase []byte
	KeyFile    string
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

func EncryptFileBytes(data []byte, opts *EncryptFileOptions) ([]byte, error) {
	return encryptFileBytes(data, opts)
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
