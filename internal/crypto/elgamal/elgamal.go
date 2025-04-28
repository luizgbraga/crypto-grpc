package elgamal

import (
	"errors"
	"fmt"
	"math/big"
)

type ElGamalKeyPair struct {
	G big.Int
	P big.Int
	Y big.Int

	X big.Int
}

func CreateElGamalKeyPair(p, g, x *big.Int) (*ElGamalKeyPair, error) {
	if p == nil || g == nil || x == nil {
		return nil, errors.New("p, g, and x must not be nil")
	}

	y := new(big.Int).Exp(g, x, p)

	return &ElGamalKeyPair{
		G: *g,
		P: *p,
		Y: *y,

		X: *x,
	}, nil
}

func Encrypt(keyPair *ElGamalKeyPair, message []byte, k *big.Int) (*big.Int, *big.Int, error) {
	m := new(big.Int).SetBytes(message)

	if m.Cmp(&keyPair.P) >= 0 {
		return nil, nil, errors.New("message must be less than P")
	}

	a := new(big.Int).Exp(&keyPair.G, k, &keyPair.P)
	temp := new(big.Int).Exp(&keyPair.Y, k, &keyPair.P)
	temp = temp.Mul(temp, m)
	b := new(big.Int).Mod(temp, &keyPair.P)

	return a, b, nil
}

func Decrypt(keyPair *ElGamalKeyPair, a, b *big.Int) ([]byte, error) {
	if a.Cmp(&keyPair.P) >= 0 || b.Cmp(&keyPair.P) >= 0 {
		return nil, fmt.Errorf("a and b must be less than P")
	}

	s := new(big.Int).Exp(a, &keyPair.X, &keyPair.P)
	sInv := new(big.Int).ModInverse(s, &keyPair.P)
	if sInv == nil {
		return nil, fmt.Errorf("could not find modular inverse of s")
	}
	m := new(big.Int).Mul(b, sInv)
	m = new(big.Int).Mod(m, &keyPair.P)
	return m.Bytes(), nil
}

func (kp *ElGamalKeyPair) EncodeToString() (privateKey, publicKey string, err error) {
	publicKey = fmt.Sprintf("%s,%s,%s", kp.Y.String(), kp.P.String(), kp.G.String())
	privateKey = fmt.Sprint(kp.X.String())

	return privateKey, publicKey, nil
}

func DecodePrivateKey(data string) (*ElGamalKeyPair, error) {
	var xStr string
	_, err := fmt.Sscanf(data, "%s", &xStr)
	if err != nil {
		return nil, errors.New("invalid private key format")
	}

	x := new(big.Int)
	if _, ok := x.SetString(xStr, 10); !ok {
		return nil, errors.New("invalid X value")
	}

	return &ElGamalKeyPair{
		X: *x,
	}, nil
}

func DecodePublicKey(data string) (*ElGamalKeyPair, error) {
	var yStr, pStr, gStr string
	_, err := fmt.Sscanf(data, "%s,%s,%s", &yStr, &pStr, &gStr)
	if err != nil {
		return nil, errors.New("invalid public key format")
	}

	y := new(big.Int)
	p := new(big.Int)
	g := new(big.Int)

	if _, ok := y.SetString(yStr, 10); !ok {
		return nil, errors.New("invalid Y value")
	}
	if _, ok := p.SetString(pStr, 10); !ok {
		return nil, errors.New("invalid P value")
	}
	if _, ok := g.SetString(gStr, 10); !ok {
		return nil, errors.New("invalid G value")
	}

	return &ElGamalKeyPair{
		Y: *y,
		P: *p,
		G: *g,
	}, nil
}
