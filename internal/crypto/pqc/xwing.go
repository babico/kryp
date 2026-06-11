package pqc

import (
	"crypto/rand"
	"errors"

	"filippo.io/mlkem768/xwing"
	"golang.org/x/crypto/chacha20poly1305"

	core "github.com/babico/data-encrypter-decrypter/internal/crypto/core"
)

type HybridXWing struct{}

func (x *HybridXWing) ID() core.AlgorithmID { return core.AlgoHybridXWing }

func (x *HybridXWing) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	kemCiphertext, sharedSecret, err := xwing.Encapsulate(key)
	if err != nil {
		return nil, errors.New("x-wing: encapsulate failed: " + err.Error())
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, errors.New("x-wing: aead setup failed: " + err.Error())
	}

	aeadNonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(aeadNonce)
	if err != nil {
		return nil, errors.New("x-wing: nonce generation failed: " + err.Error())
	}

	aeadCiphertext := aead.Seal(nil, aeadNonce, plaintext, nil)

	out := append(aeadNonce, aeadCiphertext...)
	return &core.EncryptionResult{
		Algorithm:  core.AlgoHybridXWing,
		Ciphertext: out,
		Nonce:      kemCiphertext,
	}, nil
}

func (x *HybridXWing) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	dk, err := xwing.NewKeyFromSeed(key)
	if err != nil {
		return nil, errors.New("x-wing: invalid private key: " + err.Error())
	}
	sharedSecret, err := xwing.Decapsulate(dk, nonce)
	if err != nil {
		return nil, errors.New("x-wing: decapsulate failed: " + err.Error())
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, errors.New("x-wing: aead setup failed: " + err.Error())
	}

	aeadNonceSize := aead.NonceSize()
	if len(data) < aeadNonceSize {
		return nil, errors.New("x-wing: ciphertext too short")
	}

	aeadNonce := data[:aeadNonceSize]
	aeadCiphertext := data[aeadNonceSize:]

	plaintext, err := aead.Open(nil, aeadNonce, aeadCiphertext, nil)
	if err != nil {
		return nil, errors.New("x-wing: decrypt failed: " + err.Error())
	}

	return plaintext, nil
}

func (x *HybridXWing) NonceSize() int { return xwing.CiphertextSize }

func (x *HybridXWing) KeySize() int { return xwing.SeedSize }
