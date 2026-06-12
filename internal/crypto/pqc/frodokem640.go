package pqc

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/kuking/go-frodokem"

	core "github.com/babico/kryp/internal/crypto/core"
)

type Frodo640SHAKE struct{}

var frodo640 = go_frodokem.Frodo640SHAKE()

func (f *Frodo640SHAKE) ID() core.AlgorithmID { return core.AlgoFrodo640SHAKE }

func (f *Frodo640SHAKE) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	if len(key) != frodo640.PublicKeyLen() {
		return nil, errors.New("frodokem-640-shake: invalid public key size")
	}

	kemCiphertext, sharedSecret, err := frodo640.Encapsulate(key)
	if err != nil {
		return nil, errors.New("frodokem-640-shake: encapsulate failed: " + err.Error())
	}

	aeadKey := expandFrodoSharedSecret(sharedSecret)
	aead, err := chacha20poly1305.New(aeadKey)
	if err != nil {
		return nil, errors.New("frodokem-640-shake: aead setup failed: " + err.Error())
	}

	aeadNonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(aeadNonce)
	if err != nil {
		return nil, errors.New("frodokem-640-shake: nonce generation failed: " + err.Error())
	}

	aeadCiphertext := aead.Seal(nil, aeadNonce, plaintext, nil)

	out := append(aeadNonce, aeadCiphertext...)
	return &core.EncryptionResult{
		Algorithm:  core.AlgoFrodo640SHAKE,
		Ciphertext: out,
		Nonce:      kemCiphertext,
	}, nil
}

func (f *Frodo640SHAKE) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != frodo640.SecretKeyLen() {
		return nil, errors.New("frodokem-640-shake: invalid private key size")
	}

	sharedSecret, err := frodo640.Dencapsulate(key, nonce)
	if err != nil {
		return nil, errors.New("frodokem-640-shake: decapsulate failed: " + err.Error())
	}

	aeadKey := expandFrodoSharedSecret(sharedSecret)
	aead, err := chacha20poly1305.New(aeadKey)
	if err != nil {
		return nil, errors.New("frodokem-640-shake: aead setup failed: " + err.Error())
	}

	aeadNonceSize := aead.NonceSize()
	if len(data) < aeadNonceSize {
		return nil, errors.New("frodokem-640-shake: ciphertext too short")
	}

	aeadNonce := data[:aeadNonceSize]
	aeadCiphertext := data[aeadNonceSize:]

	plaintext, err := aead.Open(nil, aeadNonce, aeadCiphertext, nil)
	if err != nil {
		return nil, errors.New("frodokem-640-shake: decrypt failed: " + err.Error())
	}

	return plaintext, nil
}

func (f *Frodo640SHAKE) NonceSize() int { return frodo640.CipherTextLen() }

func (f *Frodo640SHAKE) KeySize() int { return frodo640.PublicKeyLen() }

func expandFrodoSharedSecret(ss []byte) []byte {
	h := sha256.Sum256(ss)
	return h[:]
}
