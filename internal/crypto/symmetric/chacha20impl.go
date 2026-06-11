package symmetric

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	core "github.com/babico/data-encrypter-decrypter/internal/crypto/core"
)

type ChaCha20Poly1305 struct{}

func (c *ChaCha20Poly1305) ID() core.AlgorithmID { return core.AlgoChaCha20Poly1305 }

func (c *ChaCha20Poly1305) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("chacha20-poly1305: key must be 32 bytes")
	}
	aead, err := chacha20poly1305.New(key)
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
		Algorithm:  core.AlgoChaCha20Poly1305,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func (c *ChaCha20Poly1305) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("chacha20-poly1305: key must be 32 bytes")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, errors.New("chacha20-poly1305: decryption failed")
	}
	return plaintext, nil
}

func (c *ChaCha20Poly1305) NonceSize() int { return chacha20poly1305.NonceSize }

func (c *ChaCha20Poly1305) KeySize() int { return chacha20poly1305.KeySize }
