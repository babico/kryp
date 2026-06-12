package pqc

import (
	"crypto/rand"
	"errors"

	"github.com/shurlinet/go-hqc"

	"golang.org/x/crypto/chacha20poly1305"

	core "github.com/babico/kryp/internal/crypto/core"
)

type HQC128 struct{}

func (h *HQC128) ID() core.AlgorithmID { return core.AlgoHQC128 }

func (h *HQC128) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	publicKey, err := hqc.ParseEncapsulationKey128(key)
	if err != nil {
		return nil, errors.New("hqc-128: invalid public key: " + err.Error())
	}
	sharedSecret, kemCiphertext := publicKey.Encapsulate()

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, errors.New("hqc-128: aead setup failed: " + err.Error())
	}

	aeadNonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(aeadNonce)
	if err != nil {
		return nil, errors.New("hqc-128: nonce generation failed: " + err.Error())
	}

	aeadCiphertext := aead.Seal(nil, aeadNonce, plaintext, nil)

	out := append(aeadNonce, aeadCiphertext...)
	return &core.EncryptionResult{
		Algorithm:  core.AlgoHQC128,
		Ciphertext: out,
		Nonce:      kemCiphertext,
	}, nil
}

func (h *HQC128) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	decapsulationKey, err := hqc.ParseDecapsulationKey128(key)
	if err != nil {
		return nil, errors.New("hqc-128: invalid private key: " + err.Error())
	}

	sharedSecret, err := decapsulationKey.Decapsulate(nonce)
	if err != nil {
		return nil, errors.New("hqc-128: decapsulation failed: " + err.Error())
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, errors.New("hqc-128: aead setup failed: " + err.Error())
	}

	aeadNonceSize := aead.NonceSize()
	if len(data) < aeadNonceSize {
		return nil, errors.New("hqc-128: ciphertext too short")
	}

	aeadNonce := data[:aeadNonceSize]
	aeadCiphertext := data[aeadNonceSize:]

	plaintext, err := aead.Open(nil, aeadNonce, aeadCiphertext, nil)
	if err != nil {
		return nil, errors.New("hqc-128: decrypt failed: " + err.Error())
	}

	return plaintext, nil
}

func (h *HQC128) NonceSize() int { return hqc.CiphertextSize128 }

func (h *HQC128) KeySize() int { return hqc.SeedSize128 }
