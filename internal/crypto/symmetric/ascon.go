package symmetric

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/cipher/ascon"

	core "github.com/babico/kryp/internal/crypto/core"
)

type ASCON128 struct{}

func (a *ASCON128) ID() core.AlgorithmID { return core.AlgoASCON128 }

func (a *ASCON128) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	c, err := ascon.New(key, ascon.Ascon128)
	if err != nil {
		return nil, errors.New("ascon-128: invalid key: " + err.Error())
	}
	nonce := make([]byte, c.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := c.Seal(nil, nonce, plaintext, nil)
	return &core.EncryptionResult{
		Algorithm:  core.AlgoASCON128,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func (a *ASCON128) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	c, err := ascon.New(key, ascon.Ascon128)
	if err != nil {
		return nil, errors.New("ascon-128: invalid key: " + err.Error())
	}
	plaintext, err := c.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, errors.New("ascon-128: decryption failed (invalid key or corrupted data)")
	}
	return plaintext, nil
}

func (a *ASCON128) NonceSize() int { return 16 }

func (a *ASCON128) KeySize() int { return ascon.KeySize }
