package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"filippo.io/age"
	go_frodokem "github.com/kuking/go-frodokem"
	"github.com/shurlinet/go-hqc"
)

type kemKeyInfo struct {
	expectedLen int
	algoName    string
}

func loadKey(keyFile string, keyLen int) ([]byte, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	if len(data) < keyLen {
		return nil, fmt.Errorf("key file too short: need %d bytes, got %d", keyLen, len(data))
	}
	return data[:keyLen], nil
}

func resolveDecryptKey(passphrase []byte, keyFile string, kdfMethod KDFMethod, salt []byte, kdfParams []byte, expectedKeyLen int) ([]byte, error) {
	if len(passphrase) > 0 && kdfMethod != KDFNone {
		return DeriveKey(passphrase, kdfMethod, salt, kdfParams, expectedKeyLen)
	}
	if keyFile != "" {
		return loadKey(keyFile, expectedKeyLen)
	}
	return nil, errors.New("no passphrase or key file provided")
}

func readFullHeader(path string) (*Header, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	header, err := DecodeHeader(data)
	if err != nil {
		return nil, nil, err
	}
	headerSize := len(header.Encode())
	return header, data[headerSize:], nil
}

func deriveKeyFromOpts(opts *EncryptFileOptions, expectedKeyLen int) (key []byte, kdfMethod KDFMethod, kdfSalt, kdfParams []byte, err error) {
	if len(opts.Passphrase) > 0 {
		kdfMethod = opts.KDFMethod
		kdfSalt, err = GenerateSalt(DefaultSaltSize)
		if err != nil {
			return
		}
		switch kdfMethod {
		case KDFArgon2id:
			time := uint32(DefaultArgon2Time)
			memory := uint32(DefaultArgon2Memory)
			threads := byte(DefaultArgon2Threads)
			if opts.Argon2Time != 0 {
				time = opts.Argon2Time
			}
			if opts.Argon2Memory != 0 {
				memory = opts.Argon2Memory
			}
			if opts.Argon2Threads != 0 {
				threads = opts.Argon2Threads
			}
			kdfParams = EncodeArgon2Params(time, memory, threads)
		case KDFScrypt:
			N := uint32(DefaultScryptN)
			r := uint32(DefaultScryptR)
			p := uint32(DefaultScryptP)
			if opts.ScryptN != 0 {
				N = opts.ScryptN
			}
			if opts.ScryptR != 0 {
				r = opts.ScryptR
			}
			if opts.ScryptP != 0 {
				p = opts.ScryptP
			}
			kdfParams = EncodeScryptParams(N, r, p)
		case KDFPBKDF2:
			iter := uint32(DefaultPBKDF2Iter)
			if opts.PBKDF2Iter != 0 {
				iter = opts.PBKDF2Iter
			}
			kdfParams = EncodePBKDF2Params(iter)
		default:
			err = fmt.Errorf("unsupported KDF: %d", kdfMethod)
			return
		}
		key, err = DeriveKey(opts.Passphrase, kdfMethod, kdfSalt, kdfParams, expectedKeyLen)
		return
	}

	if opts.KeyFile != "" {
		kdfMethod = KDFNone
		key, err = loadKey(opts.KeyFile, expectedKeyLen)
		return
	}

	err = fmt.Errorf("no passphrase or key file provided")
	return
}

func resolveDecryptKeyForAlgo(algo AlgorithmID, opts *DecryptFileOptions, header *Header, expectedKeyLen int) ([]byte, error) {
	if algo == AlgoAge {
		if opts.KeyFile == "" {
			return nil, errors.New("age decryption requires an identity key file")
		}
		ageData, err := os.ReadFile(opts.KeyFile)
		if err != nil {
			return nil, err
		}
		return bytes.TrimSpace(ageData), nil
	}

	kemSizes := map[AlgorithmID]kemKeyInfo{
		AlgoMLKEM768:      {64, "ML-KEM-768"},
		AlgoMLKEM1024:     {64, "ML-KEM-1024"},
		AlgoHybridXWing:   {32, "X-Wing"},
		AlgoHPKE:          {32, "HPKE"},
		AlgoHQC128:        {hqc.SecretKeySize128, "HQC-128"},
		AlgoFrodo640SHAKE: {frodoKEM.SecretKeyLen(), "FrodoKEM-640-SHAKE"},
	}

	if info, ok := kemSizes[algo]; ok {
		if opts.KeyFile == "" {
			return nil, fmt.Errorf("%s decryption requires a decapsulation key file", info.algoName)
		}
		privKey, err := os.ReadFile(opts.KeyFile)
		if err != nil {
			return nil, err
		}
		if len(privKey) != info.expectedLen {
			return nil, fmt.Errorf("%s key must be %d bytes, got %d", info.algoName, info.expectedLen, len(privKey))
		}
		return privKey, nil
	}

	return resolveDecryptKey(opts.Passphrase, opts.KeyFile, header.KDFMethod, header.KDFSalt, header.KDFParams, expectedKeyLen)
}

func encryptWithKey(data []byte, algo AlgorithmID, key []byte, kdfMethod KDFMethod, kdfSalt, kdfParams []byte, encryptor Encryptor, origName, origPath string) ([]byte, error) {
	result, err := encryptor.Encrypt(data, key)
	if err != nil {
		return nil, err
	}

	header := &Header{
		Version:      1,
		Algorithm:    algo,
		KDFMethod:    kdfMethod,
		KDFSalt:      kdfSalt,
		KDFParams:    kdfParams,
		Nonce:        result.Nonce,
		OriginalName: origName,
		OriginalPath: origPath,
	}

	headerBytes := header.Encode()
	return append(headerBytes, result.Ciphertext...), nil
}

func encryptFileBytes(data []byte, opts *EncryptFileOptions) ([]byte, error) {
	if opts.Compatible {
		if opts.Algorithm == AlgoAge {
			return encryptAgeBytes(data, opts)
		}
		return encryptCompatible(data, opts)
	}

	if opts.Algorithm == AlgoAge {
		return encryptAgeBytes(data, opts)
	}

	if opts.Algorithm == AlgoMLKEM768 || opts.Algorithm == AlgoMLKEM1024 || opts.Algorithm == AlgoHybridXWing || opts.Algorithm == AlgoHPKE || opts.Algorithm == AlgoHQC128 || opts.Algorithm == AlgoFrodo640SHAKE {
		return encryptKEMBytes(data, opts)
	}

	encryptor, err := GetEncryptor(opts.Algorithm)
	if err != nil {
		return nil, err
	}

	key, kdfMethod, kdfSalt, kdfParams, err := deriveKeyFromOpts(opts, encryptor.KeySize())
	if err != nil {
		return nil, err
	}

	var origName, origPath string
	if opts.EmbedMetadata {
		origName = opts.OriginalNameHint
		origPath = opts.OriginalPathHint
	}

	return encryptWithKey(data, opts.Algorithm, key, kdfMethod, kdfSalt, kdfParams, encryptor, origName, origPath)
}

func encryptCompatible(data []byte, opts *EncryptFileOptions) ([]byte, error) {
	if opts.EmbedMetadata {
		return nil, errors.New("--compatible is incompatible with --embed-metadata")
	}
	if opts.UUIDRename {
		return nil, errors.New("--compatible is incompatible with --uuid-rename")
	}

	enc, err := GetEncryptor(opts.Algorithm)
	if err != nil {
		return nil, err
	}

	key, _, _, _, err := deriveKeyFromOpts(opts, enc.KeySize())
	if err != nil {
		return nil, err
	}

	result, err := enc.Encrypt(data, key)
	if err != nil {
		return nil, err
	}

	return append(result.Nonce, result.Ciphertext...), nil
}

func encryptKEMBytes(data []byte, opts *EncryptFileOptions) ([]byte, error) {
	if opts.KeyFile == "" {
		return nil, fmt.Errorf("%s encryption requires a public key file", opts.Algorithm)
	}

	pubKey, err := os.ReadFile(opts.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("reading %s public key: %w", opts.Algorithm, err)
	}

	enc, err := GetEncryptor(opts.Algorithm)
	if err != nil {
		return nil, err
	}

	result, err := enc.Encrypt(data, pubKey)
	if err != nil {
		return nil, err
	}

	var origName, origPath string
	if opts.EmbedMetadata {
		origName = opts.OriginalNameHint
		origPath = opts.OriginalPathHint
	}

	header := &Header{
		Version:      1,
		Algorithm:    opts.Algorithm,
		KDFMethod:    KDFNone,
		Nonce:        result.Nonce,
		OriginalName: origName,
		OriginalPath: origPath,
	}

	headerBytes := header.Encode()
	return append(headerBytes, result.Ciphertext...), nil
}

var frodoKEM = go_frodokem.Frodo640SHAKE()

func encryptAgeBytes(data []byte, opts *EncryptFileOptions) ([]byte, error) {
	if opts.AgeRecipient == "" {
		return nil, errors.New("age encryption requires a recipient (use --age-recipient)")
	}

	recipient, err := age.ParseX25519Recipient(opts.AgeRecipient)
	if err != nil {
		return nil, fmt.Errorf("parsing age recipient: %w", err)
	}

	buf := new(bytes.Buffer)
	w, err := age.Encrypt(buf, recipient)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(data)
	if err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}

	var origName, origPath string
	if opts.EmbedMetadata {
		origName = opts.OriginalNameHint
		origPath = opts.OriginalPathHint
	}

	header := &Header{
		Version:      1,
		Algorithm:    AlgoAge,
		KDFMethod:    KDFNone,
		OriginalName: origName,
		OriginalPath: origPath,
	}
	headerBytes := header.Encode()
	return append(headerBytes, buf.Bytes()...), nil
}
