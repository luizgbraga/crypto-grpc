package ecc

import "math/big"

type EllipticCurve struct {
	a big.Int
	b big.Int
	p big.Int
}

type Point struct {
	Px big.Int
	Py big.Int
}

type EccKeyPair struct {
	ec EllipticCurve
	G  Point

	n big.Int
}
