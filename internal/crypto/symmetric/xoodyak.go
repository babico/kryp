package symmetric

import (
	"crypto/rand"
	"errors"

	"github.com/inmcm/xoodoo/xoodyak"

	core "github.com/babico/kryp/internal/crypto/core"
)

type Xoodyak struct{}

func (x *Xoodyak) ID() core.AlgorithmID { return core.AlgoXoodyak }

func (x *Xoodyak) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	if len(key) != xoodyak.KeyLen {
		return nil, errors.New("xoodyak: invalid key size")
	}

	nonce := make([]byte, xoodyak.NonceLen)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, errors.New("xoodyak: nonce generation failed: " + err.Error())
	}

	ct, tag, err := xoodyak.CryptoEncryptAEAD(plaintext, key, nonce, nil)
	if err != nil {
		return nil, errors.New("xoodyak: encrypt failed: " + err.Error())
	}

	return &core.EncryptionResult{
		Algorithm:  core.AlgoXoodyak,
		Ciphertext: append(ct, tag...),
		Nonce:      nonce,
	}, nil
}

func (x *Xoodyak) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != xoodyak.KeyLen {
		return nil, errors.New("xoodyak: invalid key size")
	}
	if len(nonce) != xoodyak.NonceLen {
		return nil, errors.New("xoodyak: invalid nonce size")
	}

	tagSize := xoodyak.TagLen
	if len(data) < tagSize {
		return nil, errors.New("xoodyak: ciphertext too short")
	}

	ct := data[:len(data)-tagSize]
	tag := data[len(data)-tagSize:]

	pt, valid, err := xoodyak.CryptoDecryptAEAD(ct, key, nonce, nil, tag)
	if err != nil {
		return nil, errors.New("xoodyak: decrypt failed: " + err.Error())
	}
	if !valid {
		return nil, errors.New("xoodyak: authentication failed")
	}

	return pt, nil
}

func (x *Xoodyak) NonceSize() int { return xoodyak.NonceLen }

func (x *Xoodyak) KeySize() int { return xoodyak.KeyLen }
