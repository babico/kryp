package symmetric

import (
	"crypto/rand"
	"errors"

	"github.com/oasisprotocol/deoxysii"

	core "github.com/babico/kryp/internal/crypto/core"
)

type DeoxysII struct{}

func (d *DeoxysII) ID() core.AlgorithmID { return core.AlgoDeoxysII }

func (d *DeoxysII) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	aead, err := deoxysii.New(key)
	if err != nil {
		return nil, errors.New("deoxys-ii: " + err.Error())
	}

	nonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, errors.New("deoxys-ii: nonce generation failed: " + err.Error())
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return &core.EncryptionResult{
		Algorithm:  core.AlgoDeoxysII,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func (d *DeoxysII) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	aead, err := deoxysii.New(key)
	if err != nil {
		return nil, errors.New("deoxys-ii: " + err.Error())
	}

	plaintext, err := aead.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, errors.New("deoxys-ii: decrypt failed: " + err.Error())
	}

	return plaintext, nil
}

func (d *DeoxysII) NonceSize() int { return deoxysii.NonceSize }

func (d *DeoxysII) KeySize() int { return deoxysii.KeySize }
