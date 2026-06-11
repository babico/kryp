package crypto

import (
	"fmt"
	"strings"

	"github.com/babico/data-encrypter-decrypter/internal/crypto/core"
)

type AlgorithmID = core.AlgorithmID

const (
	AlgoNone              = core.AlgoNone
	AlgoXChaCha20Poly1305 = core.AlgoXChaCha20Poly1305
	AlgoChaCha20Poly1305  = core.AlgoChaCha20Poly1305
	AlgoAES256GCM         = core.AlgoAES256GCM
	AlgoSecretBox         = core.AlgoSecretBox
	AlgoAES256CTRHMAC     = core.AlgoAES256CTRHMAC
	AlgoAge               = core.AlgoAge
	AlgoMLKEM768          = core.AlgoMLKEM768
	AlgoMLKEM1024         = core.AlgoMLKEM1024
	AlgoHybridXWing       = core.AlgoHybridXWing
	AlgoHPKE              = core.AlgoHPKE
	AlgoASCON128          = core.AlgoASCON128
)

var algorithmAliases = map[string]AlgorithmID{
	"xchacha20-poly1305": AlgoXChaCha20Poly1305,
	"xchacha20":          AlgoXChaCha20Poly1305,
	"1":                  AlgoXChaCha20Poly1305,
	"chacha20-poly1305":  AlgoChaCha20Poly1305,
	"chacha20":           AlgoChaCha20Poly1305,
	"2":                  AlgoChaCha20Poly1305,
	"aes-256-gcm":        AlgoAES256GCM,
	"aes-gcm":            AlgoAES256GCM,
	"aes":                AlgoAES256GCM,
	"3":                  AlgoAES256GCM,
	"secretbox":          AlgoSecretBox,
	"nacl":               AlgoSecretBox,
	"xsalsa20":           AlgoSecretBox,
	"4":                  AlgoSecretBox,
	"aes-256-ctr-hmac":   AlgoAES256CTRHMAC,
	"aes-ctr-hmac":       AlgoAES256CTRHMAC,
	"5":                  AlgoAES256CTRHMAC,
	"age":                AlgoAge,
	"6":                  AlgoAge,
	"ml-kem-768":         AlgoMLKEM768,
	"mlkem768":           AlgoMLKEM768,
	"ml-kem":             AlgoMLKEM768,
	"kyber":              AlgoMLKEM768,
	"pqc":                AlgoMLKEM768,
	"post-quantum":       AlgoMLKEM768,
	"7":                  AlgoMLKEM768,
	"ml-kem-1024":        AlgoMLKEM1024,
	"mlkem1024":          AlgoMLKEM1024,
	"8":                  AlgoMLKEM1024,
	"x-wing":             AlgoHybridXWing,
	"xwing":              AlgoHybridXWing,
	"hybrid":             AlgoHybridXWing,
	"hybrid-xwing":       AlgoHybridXWing,
	"9":                  AlgoHybridXWing,
	"hpke":               AlgoHPKE,
	"hpke-x25519":        AlgoHPKE,
	"circl-hpke":         AlgoHPKE,
	"10":                 AlgoHPKE,
	"ascon":              AlgoASCON128,
	"ascon-128":          AlgoASCON128,
	"ascon128":           AlgoASCON128,
	"ascon128a":          AlgoASCON128,
	"11":                 AlgoASCON128,
}

func ParseAlgorithm(s string) (AlgorithmID, error) {
	algo, ok := algorithmAliases[strings.ToLower(s)]
	if !ok {
		return 0, fmt.Errorf("unknown algorithm: %s (use: xchacha20-poly1305, chacha20-poly1305, aes-256-gcm, secretbox, aes-256-ctr-hmac, age)", s)
	}
	return algo, nil
}

type KDFMethod = core.KDFMethod

const (
	KDFNone     = core.KDFNone
	KDFArgon2id = core.KDFArgon2id
	KDFScrypt   = core.KDFScrypt
	KDFPBKDF2   = core.KDFPBKDF2
)

var kdfAliases = map[string]KDFMethod{
	"none":     KDFNone,
	"raw":      KDFNone,
	"argon2id": KDFArgon2id,
	"argon2":   KDFArgon2id,
	"scrypt":   KDFScrypt,
	"pbkdf2":   KDFPBKDF2,
}

func ParseKDF(s string) (KDFMethod, error) {
	kdf, ok := kdfAliases[strings.ToLower(s)]
	if !ok {
		return 0, fmt.Errorf("unknown KDF: %s (use: argon2id, scrypt, pbkdf2, none)", s)
	}
	return kdf, nil
}

type EncryptionResult = core.EncryptionResult

type Encryptor = core.Encryptor
