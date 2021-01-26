package common

import (
	"crypto/rand"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

var ContextOne = big.NewInt(1)
var AttributeTypes = []string{"testType", "testedAt"}

func RandomBigInt(limit *big.Int) *big.Int {
	res, err := big.RandInt(rand.Reader, limit)
	if err != nil {
		panic(fmt.Sprintf("big.RandInt failed: %v", err))
	}
	return res
}

func GenerateNonce() *big.Int {
	return RandomBigInt(new(big.Int).Lsh(big.NewInt(1), uint(gabi.DefaultSystemParameters[2048].Lstatzk)))
}

func ComputeAttributes(attributeValues []string) ([]*big.Int, error) {
	if len(AttributeTypes) != len(attributeValues) {
		return nil, errors.New("Amount of attribute values don't match amount of attribute types")
	}

	// Compute attributes
	attrs := make([]*big.Int, len(attributeValues))
	for i, val := range attributeValues {
		attrs[i] = new(big.Int)
		attrs[i].SetBytes([]byte(val))

		// Let the last bit distinguish empty vs. optional attributes
		attrs[i].Lsh(attrs[i], 1)             // attr <<= 1
		attrs[i].Add(attrs[i], big.NewInt(1)) // attr += 1
	}

	return attrs, nil
}