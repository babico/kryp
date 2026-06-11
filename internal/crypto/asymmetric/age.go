package asymmetric

import (
	"errors"
	"io"

	"filippo.io/age"

	core "github.com/babico/data-encrypter-decrypter/internal/crypto/core"
)

type AgeEncryptor struct{}

func (a *AgeEncryptor) ID() core.AlgorithmID { return core.AlgoAge }

func (a *AgeEncryptor) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	parsedKey, err := age.ParseX25519Recipient(string(key))
	if err != nil {
		return nil, errors.New("age: invalid recipient key: " + err.Error())
	}
	stream, err := age.Encrypt(noopWriter{}, parsedKey)
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
		Ciphertext: noopBuf,
		Nonce:      nil,
	}, nil
}

func (a *AgeEncryptor) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	identity, err := age.ParseX25519Identity(string(key))
	if err != nil {
		return nil, errors.New("age: invalid identity key: " + err.Error())
	}
	stream, err := age.Decrypt(&noopReader{data: data}, identity)
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
		if err != nil {
			break
		}
	}
	return result, nil
}

func (a *AgeEncryptor) NonceSize() int { return 0 }

func (a *AgeEncryptor) KeySize() int { return 0 }

var noopBuf []byte

type noopWriter struct{}

func (n noopWriter) Write(p []byte) (int, error) {
	noopBuf = append(noopBuf, p...)
	return len(p), nil
}

type noopReader struct {
	data []byte
	off  int
}

func (r *noopReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	nn := copy(p, r.data[r.off:])
	r.off += nn
	return nn, nil
}
