package crypto

import (
	"crypto/mlkem"
	"errors"
	"fmt"
	"os"

	"filippo.io/mlkem768/xwing"
	"github.com/cloudflare/circl/hpke"
	"github.com/kuking/go-frodokem"
	"github.com/shurlinet/go-hqc"
)

type KEMKeypair struct {
	Algorithm   AlgorithmID
	PrivateSeed []byte
	PublicKey   []byte
}

func GenerateKEMKeypair(algo AlgorithmID) (*KEMKeypair, error) {
	switch algo {
	case AlgoMLKEM768:
		return GenerateMLKEMKeypair()
	case AlgoMLKEM1024:
		return GenerateMLKEM1024Keypair()
	case AlgoHybridXWing:
		return GenerateXWingKeypair()
	case AlgoHPKE:
		return GenerateHPKEKeypair()
	case AlgoHQC128:
		return GenerateHQC128Keypair()
	case AlgoFrodo640SHAKE:
		return GenerateFrodo640Keypair()
	default:
		return nil, fmt.Errorf("unsupported KEM algorithm: %s", algo)
	}
}

func GenerateMLKEMKeypair() (*KEMKeypair, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &KEMKeypair{
		Algorithm:   AlgoMLKEM768,
		PrivateSeed: dk.Bytes(),
		PublicKey:   dk.EncapsulationKey().Bytes(),
	}, nil
}

func GenerateMLKEM1024Keypair() (*KEMKeypair, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}
	return &KEMKeypair{
		Algorithm:   AlgoMLKEM1024,
		PrivateSeed: dk.Bytes(),
		PublicKey:   dk.EncapsulationKey().Bytes(),
	}, nil
}

func GenerateXWingKeypair() (*KEMKeypair, error) {
	dk, err := xwing.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &KEMKeypair{
		Algorithm:   AlgoHybridXWing,
		PrivateSeed: dk.Bytes(),
		PublicKey:   dk.EncapsulationKey(),
	}, nil
}

func GenerateHPKEKeypair() (*KEMKeypair, error) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	kemID, _, _ := suite.Params()
	scheme := kemID.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	privBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	pubBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &KEMKeypair{
		Algorithm:   AlgoHPKE,
		PrivateSeed: privBytes,
		PublicKey:   pubBytes,
	}, nil
}

func GenerateHQC128Keypair() (*KEMKeypair, error) {
	dk, err := hqc.GenerateKey128()
	if err != nil {
		return nil, err
	}
	return &KEMKeypair{
		Algorithm:   AlgoHQC128,
		PrivateSeed: dk.Bytes(),
		PublicKey:   dk.EncapsulationKey().Bytes(),
	}, nil
}

func GenerateFrodo640Keypair() (*KEMKeypair, error) {
	fk := go_frodokem.Frodo640SHAKE()
	pk, sk := fk.Keygen()
	return &KEMKeypair{
		Algorithm:   AlgoFrodo640SHAKE,
		PrivateSeed: sk,
		PublicKey:   pk,
	}, nil
}

func ExtractPublicKey(keyPath string) (*KEMKeypair, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	if len(data) == 64 {
		if dk, err := mlkem.NewDecapsulationKey768(data); err == nil {
			return &KEMKeypair{
				Algorithm:   AlgoMLKEM768,
				PrivateSeed: dk.Bytes(),
				PublicKey:   dk.EncapsulationKey().Bytes(),
			}, nil
		}
		if dk, err := mlkem.NewDecapsulationKey1024(data); err == nil {
			return &KEMKeypair{
				Algorithm:   AlgoMLKEM1024,
				PrivateSeed: dk.Bytes(),
				PublicKey:   dk.EncapsulationKey().Bytes(),
			}, nil
		}
	}

	if len(data) == 32 {
		if dk, err := xwing.NewKeyFromSeed(data); err == nil {
			return &KEMKeypair{
				Algorithm:   AlgoHybridXWing,
				PrivateSeed: dk.Bytes(),
				PublicKey:   dk.EncapsulationKey(),
			}, nil
		}
		suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
		kemID, _, _ := suite.Params()
		scheme := kemID.Scheme()
		pk, sk := scheme.DeriveKeyPair(data)
		privBytes, err := sk.MarshalBinary()
		if err != nil {
			return nil, err
		}
		pubBytes, err := pk.MarshalBinary()
		if err != nil {
			return nil, err
		}
		return &KEMKeypair{
			Algorithm:   AlgoHPKE,
			PrivateSeed: privBytes,
			PublicKey:   pubBytes,
		}, nil
	}

	if len(data) == hqc.SecretKeySize128 {
		if dk, err := hqc.ParseDecapsulationKey128(data); err == nil {
			return &KEMKeypair{
				Algorithm:   AlgoHQC128,
				PrivateSeed: dk.Bytes(),
				PublicKey:   dk.EncapsulationKey().Bytes(),
			}, nil
		}
	}

	return nil, errors.New("not a recognized KEM private key format")
}

func GenerateKeyPairFromSeed(algo AlgorithmID, seed []byte) (*KEMKeypair, error) {
	switch algo {
	case AlgoMLKEM768:
		if len(seed) < 64 {
			return nil, errors.New("seed too short for ML-KEM-768: need 64 bytes")
		}
		dk, err := mlkem.NewDecapsulationKey768(seed[:64])
		if err != nil {
			return nil, err
		}
		return &KEMKeypair{
			Algorithm:   AlgoMLKEM768,
			PrivateSeed: dk.Bytes(),
			PublicKey:   dk.EncapsulationKey().Bytes(),
		}, nil
	case AlgoMLKEM1024:
		if len(seed) < 64 {
			return nil, errors.New("seed too short for ML-KEM-1024: need 64 bytes")
		}
		dk, err := mlkem.NewDecapsulationKey1024(seed[:64])
		if err != nil {
			return nil, err
		}
		return &KEMKeypair{
			Algorithm:   AlgoMLKEM1024,
			PrivateSeed: dk.Bytes(),
			PublicKey:   dk.EncapsulationKey().Bytes(),
		}, nil
	case AlgoHybridXWing:
		if len(seed) < 32 {
			return nil, errors.New("seed too short for X-Wing: need 32 bytes")
		}
		dk, err := xwing.NewKeyFromSeed(seed[:32])
		if err != nil {
			return nil, err
		}
		return &KEMKeypair{
			Algorithm:   AlgoHybridXWing,
			PrivateSeed: dk.Bytes(),
			PublicKey:   dk.EncapsulationKey(),
		}, nil
	case AlgoHPKE:
		if len(seed) < 32 {
			return nil, errors.New("seed too short for HPKE: need 32 bytes")
		}
		suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
		kemID, _, _ := suite.Params()
		scheme := kemID.Scheme()
		pk, sk := scheme.DeriveKeyPair(seed[:32])
		privBytes, err := sk.MarshalBinary()
		if err != nil {
			return nil, err
		}
		pubBytes, err := pk.MarshalBinary()
		if err != nil {
			return nil, err
		}
		return &KEMKeypair{
			Algorithm:   AlgoHPKE,
			PrivateSeed: privBytes,
			PublicKey:   pubBytes,
		}, nil
	case AlgoHQC128:
		return nil, errors.New("seed-based HQC keygen not yet supported")
	case AlgoFrodo640SHAKE:
		fk := go_frodokem.Frodo640SHAKE()
		fk.OverrideRng(func(b []byte) {
			copy(b, seed)
		})
		pk, sk := fk.Keygen()
		return &KEMKeypair{
			Algorithm:   AlgoFrodo640SHAKE,
			PrivateSeed: sk,
			PublicKey:   pk,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm for seed-based keygen: %s", algo)
	}
}
