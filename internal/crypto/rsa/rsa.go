package rsa

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

type RSAKeyPair struct {
	N *big.Int
	E *big.Int

	D *big.Int
	P *big.Int
	Q *big.Int
}

func CreateRSAKeyPair(p, q, d *big.Int) (*RSAKeyPair, error) {
	if p == nil || q == nil || d == nil {
		return nil, errors.New("p, q, and d must not be nil")
	}

	n := new(big.Int).Mul(p, q)

	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus1, qMinus1)

	e := new(big.Int).ModInverse(d, phi)
	if e == nil {
		return nil, errors.New("invalid d value: no modular inverse exists")
	}

	return &RSAKeyPair{
		N: n,
		E: e,
		D: d,
		P: p,
		Q: q,
	}, nil
}

func FindPossibleDValues(p, q *big.Int, count int) ([]*big.Int, error) {
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus1, qMinus1)

	possibleDs := make([]*big.Int, 0, count)

	d := big.NewInt(3)

	for len(possibleDs) < count {
		gcd := new(big.Int)
		gcd.GCD(nil, nil, d, phi)

		e := new(big.Int).ModInverse(d, phi)

		if gcd.Cmp(big.NewInt(1)) == 0 && e != nil {
			possibleDs = append(possibleDs, new(big.Int).Set(d))
		}

		d = new(big.Int).Add(d, big.NewInt(2))
	}

	return possibleDs, nil
}

func (kp *RSAKeyPair) Encrypt(message []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(message)

	if m.Cmp(kp.N) >= 0 {
		return nil, errors.New("message too large for the key size")
	}

	// c = m^e mod n
	c := new(big.Int).Exp(m, kp.E, kp.N)

	return c.Bytes(), nil
}

func (kp *RSAKeyPair) Decrypt(ciphertext []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(ciphertext)

	// m = c^d mod n
	m := new(big.Int).Exp(c, kp.D, kp.N)

	return m.Bytes(), nil
}

func (kp *RSAKeyPair) EncodeToString() (privateKey, publicKey string, err error) {
	publicKey = fmt.Sprintf("%s,%s", kp.N.String(), kp.E.String())
	privateKey = fmt.Sprintf("%s,%s", kp.N.String(), kp.D.String())

	return privateKey, publicKey, nil
}

func DecodePrivateKey(data string) (*RSAKeyPair, error) {
	var nStr, dStr string
	_, err := fmt.Sscanf(data, "%s,%s", &nStr, &dStr)
	if err != nil {
		return nil, errors.New("invalid private key format")
	}

	n := new(big.Int)
	d := new(big.Int)

	if _, ok := n.SetString(nStr, 10); !ok {
		return nil, errors.New("invalid N value")
	}
	if _, ok := d.SetString(dStr, 10); !ok {
		return nil, errors.New("invalid D value")
	}

	return &RSAKeyPair{
		N: n,
		E: nil,
		D: d,
		P: nil,
		Q: nil,
	}, nil
}

func DecodePublicKey(data string) (*RSAKeyPair, error) {
	keys := strings.Split(data, ",")
	if len(keys) != 2 {
		return nil, errors.New("invalid public key format")
	}
	nStr, eStr := keys[0], keys[1]

	n := new(big.Int)
	e := new(big.Int)

	if _, ok := n.SetString(nStr, 10); !ok {
		return nil, errors.New("invalid N value")
	}
	if _, ok := e.SetString(eStr, 10); !ok {
		return nil, errors.New("invalid E value")
	}

	return &RSAKeyPair{
		N: n,
		E: e,
		D: nil,
		P: nil,
		Q: nil,
	}, nil
}
