package main

import (
	"crypto/rand"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

func main() {
	var err error
	issuerPk, err = gabi.NewPublicKeyFromXML(issuerPkXml)
	issuerSk, err = gabi.NewPrivateKeyFromXML(issuerSkXml, false)
	if err != nil {
		panic("Error loading issuer keys")
	}

	ClientStart()
}

// ---

var contextOne = big.NewInt(1)
var attributeTypes = []string{"testType", "testedAt"}

func randomBigInt(limit *big.Int) *big.Int {
	res, err := big.RandInt(rand.Reader, limit)
	if err != nil {
		panic(fmt.Sprintf("big.RandInt failed: %v", err))
	}
	return res
}

func generateNonce() *big.Int {
	return randomBigInt(new(big.Int).Lsh(big.NewInt(1), uint(gabi.DefaultSystemParameters[2048].Lstatzk)))
}

func computeAttributes(attributeValues []string) ([]*big.Int, error) {
	if len(attributeTypes) != len(attributeValues) {
		return nil, errors.New("Amount of attribute values don't match amount of attribute types")
	}

	// Compute attributes
	attrs := make([]*big.Int, len(attributeTypes))
	for i, val := range attributeValues {
		attrs[i] = new(big.Int)
		attrs[i].SetBytes([]byte(val))

		// Let the last bit distinguish empty vs. optional attributes
		attrs[i].Lsh(attrs[i], 1)             // attr <<= 1
		attrs[i].Add(attrs[i], big.NewInt(1)) // attr += 1
	}

	return attrs, nil
}
