package keystore

import (
	"errors"
	"fmt"
	"sync"

	"github.com/luizgbraga/crypto-go/internal/crypto"
)

type ServerKeyStore struct {
	publicKeys map[string]map[crypto.Algorithm][]byte
	mutex      sync.Mutex
}

func NewServerKeyStore() *ServerKeyStore {
	return &ServerKeyStore{
		publicKeys: make(map[string]map[crypto.Algorithm][]byte),
	}
}

func (ks *ServerKeyStore) StorePublicKey(userID string, algorithm crypto.Algorithm, publicKey []byte) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	if _, exists := ks.publicKeys[userID]; !exists {
		ks.publicKeys[userID] = make(map[crypto.Algorithm][]byte)
	}

	ks.publicKeys[userID][algorithm] = publicKey
	return nil
}

func (ks *ServerKeyStore) GetPublicKey(userID string, algorithm crypto.Algorithm) ([]byte, error) {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	userKeys, exists := ks.publicKeys[userID]
	if !exists {
		return nil, errors.New("no keys found for user")
	}

	key, exists := userKeys[algorithm]
	if !exists {
		return nil, fmt.Errorf("no %s key found for user", algorithm)
	}

	return key, nil
}

func (ks *ServerKeyStore) StorePrivateKey(algorithm crypto.Algorithm, privateKey []byte) error {
	return errors.New("server does not store private keys")
}

func (ks *ServerKeyStore) GetPrivateKey(algorithm crypto.Algorithm) ([]byte, error) {
	return nil, errors.New("server does not store private keys")
}

func (ks *ServerKeyStore) Display() {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	fmt.Println("\nPublic keys stored in server:")

	for user, keys := range ks.publicKeys {
		fmt.Printf("User %s:\n", user)
		for algo, key := range keys {
			if len(key) == 0 {
				fmt.Printf("  %s: [unset]\n", algo)
			} else {
				fmt.Printf("  %s: %s\n", algo, key)
			}
		}
	}
}
