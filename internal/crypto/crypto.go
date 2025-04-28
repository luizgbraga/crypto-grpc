package crypto

type Algorithm string

const (
	RSA     Algorithm = "RSA"
	ElGamal Algorithm = "ElGamal"
)

type KeyStore interface {
	StorePublicKey(userID string, algorithm Algorithm, publicKey []byte) error
	GetPublicKey(userID string, algorithm Algorithm) ([]byte, error)
	StorePrivateKey(algorithm Algorithm, privateKey []byte) error
	GetPrivateKey(algorithm Algorithm) ([]byte, error)
	Display()
}
