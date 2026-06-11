package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const (
	DefaultArgon2Time    = 3
	DefaultArgon2Memory  = 64 * 1024
	DefaultArgon2Threads = 4
	DefaultScryptN       = 32768
	DefaultScryptR       = 8
	DefaultScryptP       = 1
	DefaultPBKDF2Iter    = 600000
	DefaultSaltSize      = 16
)

func DeriveKey(passphrase []byte, kdfMethod KDFMethod, salt []byte, params []byte, keyLen int) ([]byte, error) {
	switch kdfMethod {
	case KDFNone:
		return nil, errors.New("KDFNone requires raw key, not derivation")
	case KDFArgon2id:
		return deriveArgon2id(passphrase, salt, params, keyLen)
	case KDFScrypt:
		return deriveScrypt(passphrase, salt, params, keyLen)
	case KDFPBKDF2:
		return derivePBKDF2(passphrase, salt, params, keyLen)
	default:
		return nil, errors.New("unknown KDF method")
	}
}

func deriveArgon2id(passphrase []byte, salt []byte, params []byte, keyLen int) ([]byte, error) {
	if len(params) < 9 {
		return nil, errors.New("invalid Argon2id params")
	}
	time := binary.BigEndian.Uint32(params[0:4])
	memory := binary.BigEndian.Uint32(params[4:8])
	threads := params[8]
	return argon2.IDKey(passphrase, salt, time, memory, uint8(threads), uint32(keyLen)), nil
}

func deriveScrypt(passphrase []byte, salt []byte, params []byte, keyLen int) ([]byte, error) {
	if len(params) < 12 {
		return nil, errors.New("invalid scrypt params")
	}
	N := int(binary.BigEndian.Uint32(params[0:4]))
	r := int(binary.BigEndian.Uint32(params[4:8]))
	p := int(binary.BigEndian.Uint32(params[8:12]))
	key, err := scrypt.Key(passphrase, salt, N, r, p, keyLen)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func derivePBKDF2(passphrase []byte, salt []byte, params []byte, keyLen int) ([]byte, error) {
	if len(params) < 4 {
		return nil, errors.New("invalid PBKDF2 params")
	}
	iterations := int(binary.BigEndian.Uint32(params[0:4]))
	return pbkdf2.Key(passphrase, salt, iterations, keyLen, sha256.New), nil
}

func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func EncodeArgon2Params(time uint32, memory uint32, threads byte) []byte {
	buf := make([]byte, 9)
	binary.BigEndian.PutUint32(buf[0:4], time)
	binary.BigEndian.PutUint32(buf[4:8], memory)
	buf[8] = threads
	return buf
}

func EncodeScryptParams(N uint32, r uint32, p uint32) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[0:4], N)
	binary.BigEndian.PutUint32(buf[4:8], r)
	binary.BigEndian.PutUint32(buf[8:12], p)
	return buf
}

func EncodePBKDF2Params(iterations uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, iterations)
	return buf
}
