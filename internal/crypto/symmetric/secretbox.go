package symmetric

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/nacl/secretbox"

	core "github.com/babico/kryp/internal/crypto/core"
)

type SecretBox struct{}

func (s *SecretBox) ID() core.AlgorithmID { return core.AlgoSecretBox }

func (s *SecretBox) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	if len(key) != 32 {
		return nil, errors.New("secretbox: key must be 32 bytes")
	}
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}
	var keyArr [32]byte
	copy(keyArr[:], key)

	out := secretbox.Seal(nil, plaintext, &nonce, &keyArr)
	return &core.EncryptionResult{
		Algorithm:  core.AlgoSecretBox,
		Ciphertext: out,
		Nonce:      nonce[:],
	}, nil
}

func (s *SecretBox) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("secretbox: key must be 32 bytes")
	}
	var nonceArr [24]byte
	copy(nonceArr[:], nonce)
	var keyArr [32]byte
	copy(keyArr[:], key)

	plaintext, ok := secretbox.Open(nil, data, &nonceArr, &keyArr)
	if !ok {
		return nil, errors.New("secretbox: decryption failed (invalid key or corrupted data)")
	}
	return plaintext, nil
}

func (s *SecretBox) NonceSize() int { return 24 }

func (s *SecretBox) KeySize() int { return 32 }
