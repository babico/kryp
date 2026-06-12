package symmetric

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	core "github.com/babico/kryp/internal/crypto/core"
)

type XChaCha20 struct{}

func (x *XChaCha20) ID() core.AlgorithmID { return core.AlgoXChaCha20Poly1305 }

func (x *XChaCha20) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("xchacha20-poly1305: key must be 32 bytes")
	}
	aead, err := chacha20poly1305.NewX(key)
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
		Algorithm:  core.AlgoXChaCha20Poly1305,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func (x *XChaCha20) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("xchacha20-poly1305: key must be 32 bytes")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, errors.New("xchacha20-poly1305: decryption failed")
	}
	return plaintext, nil
}

func (x *XChaCha20) NonceSize() int { return chacha20poly1305.NonceSizeX }

func (x *XChaCha20) KeySize() int { return chacha20poly1305.KeySize }
