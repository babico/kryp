package pqc

import (
	"crypto/mlkem"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	core "github.com/babico/kryp/internal/crypto/core"
)

type MLKEM768 struct{}

func (m *MLKEM768) ID() core.AlgorithmID { return core.AlgoMLKEM768 }

func (m *MLKEM768) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	publicKey, err := mlkem.NewEncapsulationKey768(key)
	if err != nil {
		return nil, errors.New("ml-kem-768: invalid public key: " + err.Error())
	}
	sharedSecret, kemCiphertext := publicKey.Encapsulate()

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, errors.New("ml-kem-768: aead setup failed: " + err.Error())
	}

	aeadNonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(aeadNonce)
	if err != nil {
		return nil, errors.New("ml-kem-768: nonce generation failed: " + err.Error())
	}

	aeadCiphertext := aead.Seal(nil, aeadNonce, plaintext, nil)

	out := append(aeadNonce, aeadCiphertext...)
	return &core.EncryptionResult{
		Algorithm:  core.AlgoMLKEM768,
		Ciphertext: out,
		Nonce:      kemCiphertext,
	}, nil
}

func (m *MLKEM768) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	decapsulationKey, err := mlkem.NewDecapsulationKey768(key)
	if err != nil {
		return nil, errors.New("ml-kem-768: invalid private key: " + err.Error())
	}
	sharedSecret, err := decapsulationKey.Decapsulate(nonce)
	if err != nil {
		return nil, errors.New("ml-kem-768: decapsulation failed: " + err.Error())
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, errors.New("ml-kem-768: aead setup failed: " + err.Error())
	}

	aeadNonceSize := aead.NonceSize()
	if len(data) < aeadNonceSize {
		return nil, errors.New("ml-kem-768: ciphertext too short")
	}

	aeadNonce := data[:aeadNonceSize]
	aeadCiphertext := data[aeadNonceSize:]

	plaintext, err := aead.Open(nil, aeadNonce, aeadCiphertext, nil)
	if err != nil {
		return nil, errors.New("ml-kem-768: decrypt failed: " + err.Error())
	}

	return plaintext, nil
}

func (m *MLKEM768) NonceSize() int { return mlkem.CiphertextSize768 }

func (m *MLKEM768) KeySize() int { return mlkem.SeedSize }
