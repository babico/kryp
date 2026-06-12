package symmetric

import (
	"crypto/rand"
	"errors"

	"github.com/fernandezvara/aesgcmsiv"

	core "github.com/babico/kryp/internal/crypto/core"
)

type AES256GCMSIV struct{}

func (a *AES256GCMSIV) ID() core.AlgorithmID { return core.AlgoAES256GCMSIV }

func (a *AES256GCMSIV) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	if len(key) != 32 {
		return nil, errors.New("aes-256-gcm-siv: key must be 32 bytes")
	}
	c, err := aesgcmsiv.New(key)
	if err != nil {
		return nil, errors.New("aes-256-gcm-siv: " + err.Error())
	}
	nonce := make([]byte, c.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := c.Seal(nil, nonce, plaintext, nil)
	return &core.EncryptionResult{
		Algorithm:  core.AlgoAES256GCMSIV,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func (a *AES256GCMSIV) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("aes-256-gcm-siv: key must be 32 bytes")
	}
	c, err := aesgcmsiv.New(key)
	if err != nil {
		return nil, errors.New("aes-256-gcm-siv: " + err.Error())
	}
	plaintext, err := c.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, errors.New("aes-256-gcm-siv: decryption failed")
	}
	return plaintext, nil
}

func (a *AES256GCMSIV) NonceSize() int { return aesgcmsiv.NonceSize }

func (a *AES256GCMSIV) KeySize() int { return 32 }
