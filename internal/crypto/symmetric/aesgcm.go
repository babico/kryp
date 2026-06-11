package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	core "github.com/babico/data-encrypter-decrypter/internal/crypto/core"
)

type AES256GCM struct{}

func (a *AES256GCM) ID() core.AlgorithmID { return core.AlgoAES256GCM }

func (a *AES256GCM) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	if len(key) != 32 {
		return nil, errors.New("aes-256-gcm: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return &core.EncryptionResult{
		Algorithm:  core.AlgoAES256GCM,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func (a *AES256GCM) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("aes-256-gcm: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, errors.New("aes-256-gcm: decryption failed")
	}
	return plaintext, nil
}

func (a *AES256GCM) NonceSize() int { return 12 }

func (a *AES256GCM) KeySize() int { return 32 }
