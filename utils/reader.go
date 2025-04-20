package utils

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
	"strings"
)

func Read(message ...string) string {
	if len(message) > 0 {
		fmt.Print(message[0])
	}
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

func ReadBytes(message ...string) ([]byte, error) {
	if len(message) > 0 {
		fmt.Print(message[0])
	}
	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	return text[:len(text)-1], nil
}

func ReadBigInt(message ...string) (big.Int, error) {
	bigIntString := Read(message...)
	bigInt := new(big.Int)
	if _, ok := bigInt.SetString(bigIntString, 10); !ok {
		return *bigInt, fmt.Errorf("invalid number format")
	}
	return *bigInt, nil
}

func ReadPrime(message ...string) (big.Int, error) {
	primeString := Read(message...)
	prime := new(big.Int)
	if _, ok := prime.SetString(primeString, 10); !ok {
		return *prime, fmt.Errorf("invalid number format")
	}
	if !prime.ProbablyPrime(20) {
		return *prime, fmt.Errorf("%d is not prime", prime)
	}
	return *prime, nil
}
