package elgamal

import (
	"fmt"
	"math/big"

	"github.com/luizgbraga/crypto-go/internal/crypto"
)

type ElGamalProvider struct {
	keyStore crypto.KeyStore
	userID   string
	keyPair  *ElGamalKeyPair
}

func NewElGamalProvider(keyStore crypto.KeyStore, userID string) *ElGamalProvider {
	return &ElGamalProvider{
		keyStore: keyStore,
		userID:   userID,
		keyPair:  nil,
	}
}

func (p *ElGamalProvider) StorePublicKey(userID string, publicKeyData []byte) error {
	return p.keyStore.StorePublicKey(userID, crypto.ElGamal, publicKeyData)
}

func (p *ElGamalProvider) StoreKeyPair(primeP, generatorG, secretX big.Int) error {
	keyPair, err := CreateElGamalKeyPair(&primeP, &generatorG, &secretX)
	if err != nil {
		return err
	}

	p.keyPair = keyPair

	privateKeyStr, publicKeyStr, err := keyPair.EncodeToString()
	if err != nil {
		return err
	}

	err = p.keyStore.StorePrivateKey(crypto.ElGamal, []byte(privateKeyStr))
	if err != nil {
		return err
	}

	return p.keyStore.StorePublicKey(p.userID, crypto.ElGamal, []byte(publicKeyStr))
}

func (p *ElGamalProvider) Encrypt(message []byte, recipientID string, k big.Int) ([]byte, error) {
	recipientKeyBytes, err := p.keyStore.GetPublicKey(recipientID, crypto.ElGamal)
	if err != nil {
		return nil, err
	}

	recipientKey, err := DecodePublicKey(string(recipientKeyBytes))
	if err != nil {
		return nil, err
	}

	if k.Cmp(&recipientKey.P) >= 0 || k.Cmp(big.NewInt(0)) <= 0 {
		return nil, fmt.Errorf("k must be greater than 0 and less than P")
	}

	a, b, err := Encrypt(recipientKey, message, &k)
	if err != nil {
		return nil, err
	}

	return append(a.Bytes(), b.Bytes()...), nil
}

func (p *ElGamalProvider) Decrypt(ciphertext []byte) ([]byte, error) {
	if p.keyPair == nil {
		privateKeyBytes, err := p.keyStore.GetPrivateKey(crypto.ElGamal)
		if err != nil {
			return nil, fmt.Errorf("private key not available: %v", err)
		}

		keyPair, err := DecodePrivateKey(string(privateKeyBytes))
		if err != nil {
			return nil, err
		}

		p.keyPair = keyPair
	}

	ciphertextLength := len(ciphertext) / 2
	a := new(big.Int).SetBytes(ciphertext[:ciphertextLength])
	b := new(big.Int).SetBytes(ciphertext[ciphertextLength:])

	m, err := Decrypt(p.keyPair, a, b)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (p *ElGamalProvider) GetPublicKey() ([]byte, error) {
	if p.keyPair == nil {
		privateKeyBytes, err := p.keyStore.GetPrivateKey(crypto.ElGamal)
		if err != nil {
			return nil, fmt.Errorf("key pair not available: %v", err)
		}

		keyPair, err := DecodePrivateKey(string(privateKeyBytes))
		if err != nil {
			return nil, err
		}

		p.keyPair = keyPair
	}

	_, publicKeyStr, err := p.keyPair.EncodeToString()
	return []byte(publicKeyStr), err
}
