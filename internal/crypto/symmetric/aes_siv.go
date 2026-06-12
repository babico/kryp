package symmetric

import (
	"crypto/rand"
	"errors"

	aessiv "github.com/jedisct1/go-aes-siv"

	core "github.com/babico/kryp/internal/crypto/core"
)

type AES256SIV struct{}

func (a *AES256SIV) ID() core.AlgorithmID { return core.AlgoAES256SIV }

func (a *AES256SIV) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	aead, err := aessiv.New(key)
	if err != nil {
		return nil, errors.New("aes-256-siv: " + err.Error())
	}

	nonce := make([]byte, 16)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, errors.New("aes-256-siv: nonce generation failed: " + err.Error())
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return &core.EncryptionResult{
		Algorithm:  core.AlgoAES256SIV,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func (a *AES256SIV) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	aead, err := aessiv.New(key)
	if err != nil {
		return nil, errors.New("aes-256-siv: " + err.Error())
	}

	plaintext, err := aead.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, errors.New("aes-256-siv: decrypt failed: " + err.Error())
	}

	return plaintext, nil
}

func (a *AES256SIV) NonceSize() int { return 16 }

func (a *AES256SIV) KeySize() int { return aessiv.KeySize512 }
