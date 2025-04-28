package keystore

import (
	"errors"
	"fmt"
	"sync"

	"github.com/luizgbraga/crypto-go/internal/crypto"
)

type ClientKeyStore struct {
	privateKeys map[crypto.Algorithm][]byte
	publicKeys  map[string]map[crypto.Algorithm][]byte
	userID      string
	mutex       sync.Mutex
}

func NewClientKeyStore(userID string) *ClientKeyStore {
	return &ClientKeyStore{
		privateKeys: make(map[crypto.Algorithm][]byte),
		publicKeys:  make(map[string]map[crypto.Algorithm][]byte),
		userID:      userID,
	}
}

func (ks *ClientKeyStore) StorePublicKey(userID string, algorithm crypto.Algorithm, publicKey []byte) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	if _, exists := ks.publicKeys[userID]; !exists {
		ks.publicKeys[userID] = make(map[crypto.Algorithm][]byte)
	}

	ks.publicKeys[userID][algorithm] = publicKey
	return nil
}

func (ks *ClientKeyStore) GetPublicKey(userID string, algorithm crypto.Algorithm) ([]byte, error) {
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

func (ks *ClientKeyStore) StorePrivateKey(algorithm crypto.Algorithm, privateKey []byte) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	ks.privateKeys[algorithm] = privateKey
	return nil
}

func (ks *ClientKeyStore) GetPrivateKey(algorithm crypto.Algorithm) ([]byte, error) {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	key, exists := ks.privateKeys[algorithm]
	if !exists {
		return nil, fmt.Errorf("no %s private key found", algorithm)
	}

	return key, nil
}

func (ks *ClientKeyStore) Display() {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	fmt.Println("\nYour private keys:")
	if len(ks.privateKeys) == 0 {
		fmt.Println("No private keys found.")
		return
	}
	for algo, key := range ks.privateKeys {
		if len(key) == 0 {
			fmt.Printf("%s: [unset]\n", algo)
		} else {
			fmt.Printf("%s: %s\n", algo, key)
		}
	}
}
