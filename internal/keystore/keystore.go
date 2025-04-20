package keystore

import (
	"github.com/luizgbraga/crypto-go/internal/crypto"
)

type KeyStore interface {
	StorePublicKey(userID string, algorithm crypto.Algorithm, publicKey []byte) error
	GetPublicKey(userID string, algorithm crypto.Algorithm) ([]byte, error)
	StorePrivateKey(algorithm crypto.Algorithm, privateKey []byte) error
	GetPrivateKey(algorithm crypto.Algorithm) ([]byte, error)
	Display()
}
