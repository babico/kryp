package asymmetric

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/hpke"

	core "github.com/babico/kryp/internal/crypto/core"
)

var hpkeSuite = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
var hpkeInfo = []byte("encrypt-cli-hpke-v1")

type HPKEEncryptor struct{}

func (h *HPKEEncryptor) ID() core.AlgorithmID { return core.AlgoHPKE }

func (h *HPKEEncryptor) Encrypt(plaintext []byte, key []byte) (*core.EncryptionResult, error) {
	kemID, _, _ := hpkeSuite.Params()
	scheme := kemID.Scheme()
	pk, err := scheme.UnmarshalBinaryPublicKey(key)
	if err != nil {
		return nil, errors.New("hpke: invalid public key: " + err.Error())
	}

	sender, err := hpkeSuite.NewSender(pk, hpkeInfo)
	if err != nil {
		return nil, errors.New("hpke: new sender failed: " + err.Error())
	}

	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, errors.New("hpke: setup failed: " + err.Error())
	}

	ct, err := sealer.Seal(plaintext, nil)
	if err != nil {
		return nil, errors.New("hpke: encrypt failed: " + err.Error())
	}

	return &core.EncryptionResult{
		Algorithm:  core.AlgoHPKE,
		Ciphertext: ct,
		Nonce:      enc,
	}, nil
}

func (h *HPKEEncryptor) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	kemID, _, _ := hpkeSuite.Params()
	scheme := kemID.Scheme()
	sk, err := scheme.UnmarshalBinaryPrivateKey(key)
	if err != nil {
		return nil, errors.New("hpke: invalid private key: " + err.Error())
	}

	receiver, err := hpkeSuite.NewReceiver(sk, hpkeInfo)
	if err != nil {
		return nil, errors.New("hpke: new receiver failed: " + err.Error())
	}

	opener, err := receiver.Setup(nonce)
	if err != nil {
		return nil, errors.New("hpke: receiver setup failed: " + err.Error())
	}

	pt, err := opener.Open(data, nil)
	if err != nil {
		return nil, errors.New("hpke: decrypt failed: " + err.Error())
	}

	return pt, nil
}

func (h *HPKEEncryptor) NonceSize() int { return 0 }

func (h *HPKEEncryptor) KeySize() int { return 0 }
