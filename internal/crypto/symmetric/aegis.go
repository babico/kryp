package symmetric

import (
	"crypto/rand"
	"errors"

	"github.com/ericlagergren/aegis"

	core "github.com/babico/kryp/internal/crypto/core"
)

type AEGIS128L struct{}

func (a *AEGIS128L) ID() core.AlgorithmID { return core.AlgoAEGIS128L }

func (a *AEGIS128L) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	if len(key) != aegis.KeySize128L {
		return nil, errors.New("aegis-128l: key must be 16 bytes")
	}
	c, err := aegis.New(key)
	if err != nil {
		return nil, errors.New("aegis-128l: " + err.Error())
	}
	nonce := make([]byte, c.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := c.Seal(nil, nonce, plaintext, nil)
	return &core.EncryptionResult{
		Algorithm:  core.AlgoAEGIS128L,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func (a *AEGIS128L) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != aegis.KeySize128L {
		return nil, errors.New("aegis-128l: key must be 16 bytes")
	}
	c, err := aegis.New(key)
	if err != nil {
		return nil, errors.New("aegis-128l: " + err.Error())
	}
	plaintext, err := c.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, errors.New("aegis-128l: decryption failed")
	}
	return plaintext, nil
}

func (a *AEGIS128L) NonceSize() int { return aegis.NonceSize128L }

func (a *AEGIS128L) KeySize() int { return aegis.KeySize128L }

type AEGIS256 struct{}

func (a *AEGIS256) ID() core.AlgorithmID { return core.AlgoAEGIS256 }

func (a *AEGIS256) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	if len(key) != aegis.KeySize256 {
		return nil, errors.New("aegis-256: key must be 32 bytes")
	}
	c, err := aegis.New(key)
	if err != nil {
		return nil, errors.New("aegis-256: " + err.Error())
	}
	nonce := make([]byte, c.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := c.Seal(nil, nonce, plaintext, nil)
	return &core.EncryptionResult{
		Algorithm:  core.AlgoAEGIS256,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func (a *AEGIS256) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != aegis.KeySize256 {
		return nil, errors.New("aegis-256: key must be 32 bytes")
	}
	c, err := aegis.New(key)
	if err != nil {
		return nil, errors.New("aegis-256: " + err.Error())
	}
	plaintext, err := c.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, errors.New("aegis-256: decryption failed")
	}
	return plaintext, nil
}

func (a *AEGIS256) NonceSize() int { return aegis.NonceSize256 }

func (a *AEGIS256) KeySize() int { return aegis.KeySize256 }
