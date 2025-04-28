package rsa

import (
	"errors"
	"math/big"

	"github.com/luizgbraga/crypto-go/internal/crypto"
)

type RSAProvider struct {
	keyStore crypto.KeyStore
	userID   string
	keyPair  *RSAKeyPair
}

func NewRSAProvider(keyStore crypto.KeyStore, userID string) *RSAProvider {
	return &RSAProvider{
		keyStore: keyStore,
		userID:   userID,
		keyPair:  nil,
	}
}

func (p *RSAProvider) StorePublicKey(userID string, publicKeyData []byte) error {
	return p.keyStore.StorePublicKey(userID, crypto.RSA, publicKeyData)
}

func (p *RSAProvider) Encrypt(message []byte, recipientID string) ([]byte, error) {
	recipientKeyBytes, err := p.keyStore.GetPublicKey(recipientID, crypto.RSA)
	if err != nil {
		return nil, err
	}

	recipientKey, err := DecodePublicKey(string(recipientKeyBytes))
	if err != nil {
		return nil, err
	}

	return recipientKey.Encrypt(message)
}

func (p *RSAProvider) Decrypt(ciphertext []byte) ([]byte, error) {
	if p.keyPair == nil {
		privateKeyBytes, err := p.keyStore.GetPrivateKey(crypto.RSA)
		if err != nil {
			return nil, errors.New("private key not available")
		}

		keyPair, err := DecodePrivateKey(string(privateKeyBytes))
		if err != nil {
			return nil, err
		}

		p.keyPair = keyPair
	}

	return p.keyPair.Decrypt(ciphertext)
}

func (p *RSAProvider) GetPublicKey() ([]byte, error) {
	if p.keyPair == nil {
		privateKeyBytes, err := p.keyStore.GetPrivateKey(crypto.RSA)
		if err != nil {
			return nil, errors.New("key pair not available")
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

func (p *RSAProvider) StoreKeyPair(primeP, primeQ, dValue big.Int) error {
	keyPair, err := CreateRSAKeyPair(&primeP, &primeQ, &dValue)
	if err != nil {
		return err
	}

	p.keyPair = keyPair

	privateKeyStr, publicKeyStr, err := keyPair.EncodeToString()
	if err != nil {
		return err
	}

	err = p.keyStore.StorePrivateKey(crypto.RSA, []byte(privateKeyStr))
	if err != nil {
		return err
	}

	return p.keyStore.StorePublicKey(p.userID, crypto.RSA, []byte(publicKeyStr))
}

func (p *RSAProvider) GetPossibleDValues(primeP, primeQ big.Int, count int) ([]string, error) {
	dValues, err := FindPossibleDValues(&primeP, &primeQ, count)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(dValues))
	for i, d := range dValues {
		result[i] = d.String()
	}

	return result, nil
}
