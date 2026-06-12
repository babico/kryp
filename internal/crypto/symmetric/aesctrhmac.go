package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	core "github.com/babico/kryp/internal/crypto/core"
)

type AES256CTRHMAC struct{}

func (a *AES256CTRHMAC) ID() core.AlgorithmID { return core.AlgoAES256CTRHMAC }

func (a *AES256CTRHMAC) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	if len(key) != 64 {
		return nil, errors.New("aes-256-ctr+hmac: key must be 64 bytes (32 for AES + 32 for HMAC)")
	}
	aesKey := key[:32]
	macKey := key[32:]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aes.BlockSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, nonce)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	mac := hmac.New(sha256.New, macKey)
	mac.Write(nonce)
	mac.Write(ciphertext)
	tag := mac.Sum(nil)

	return &core.EncryptionResult{
		Algorithm:  core.AlgoAES256CTRHMAC,
		Ciphertext: append(tag, ciphertext...),
		Nonce:      nonce,
	}, nil
}

func (a *AES256CTRHMAC) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != 64 {
		return nil, errors.New("aes-256-ctr+hmac: key must be 64 bytes (32 for AES + 32 for HMAC)")
	}
	aesKey := key[:32]
	macKey := key[32:]

	if len(data) < sha256.Size {
		return nil, errors.New("aes-256-ctr+hmac: ciphertext too short")
	}
	tag := data[:sha256.Size]
	ciphertext := data[sha256.Size:]

	mac := hmac.New(sha256.New, macKey)
	mac.Write(nonce)
	mac.Write(ciphertext)
	expectedTag := mac.Sum(nil)

	if !hmac.Equal(tag, expectedTag) {
		return nil, errors.New("aes-256-ctr+hmac: HMAC verification failed (invalid key or corrupted data)")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, nonce)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func (a *AES256CTRHMAC) NonceSize() int { return aes.BlockSize }

func (a *AES256CTRHMAC) KeySize() int { return 64 }
