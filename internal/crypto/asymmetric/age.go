package asymmetric

import (
	"bytes"
	"errors"
	"io"

	"filippo.io/age"

	core "github.com/babico/kryp/internal/crypto/core"
)

type AgeEncryptor struct{}

func (a *AgeEncryptor) ID() core.AlgorithmID { return core.AlgoAge }

func (a *AgeEncryptor) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	parsedKey, err := age.ParseX25519Recipient(string(key))
	if err != nil {
		return nil, errors.New("age: invalid recipient key: " + err.Error())
	}
	var buf bytes.Buffer
	stream, err := age.Encrypt(&buf, parsedKey)
	if err != nil {
		return nil, err
	}
	_, err = stream.Write(plaintext)
	if err != nil {
		return nil, err
	}
	err = stream.Close()
	if err != nil {
		return nil, err
	}
	return &core.EncryptionResult{
		Algorithm:  core.AlgoAge,
		Ciphertext: buf.Bytes(),
		Nonce:      nil,
	}, nil
}

func (a *AgeEncryptor) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	identity, err := age.ParseX25519Identity(string(key))
	if err != nil {
		return nil, errors.New("age: invalid identity key: " + err.Error())
	}
	stream, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return nil, err
	}
	var result []byte
	buf := make([]byte, 4096)
	for {
		n, err := stream.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (a *AgeEncryptor) NonceSize() int { return 0 }

func (a *AgeEncryptor) KeySize() int { return 0 }
