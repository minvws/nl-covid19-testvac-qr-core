package common

import (
	"crypto/rand"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

var BigOne = big.NewInt(1)
var GabiSystemParameters = gabi.DefaultSystemParameters[2048]

var AttributeTypes = []string{"testType", "testedAt"}

// RandomBigInt returns a random big integer value in the range
// [0,(2^numBits)-1], inclusive.
func RandomBigInt(numBits uint) *big.Int {
	t := new(big.Int).Lsh(BigOne, numBits)

	r, err := big.RandInt(rand.Reader, t)
	if err != nil {
		panic(fmt.Sprintf("big.RandInt failed: %v", err))
	}

	return r
}

func GenerateNonce() *big.Int {
	return RandomBigInt(GabiSystemParameters.Lstatzk)
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