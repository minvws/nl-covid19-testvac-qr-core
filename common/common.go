package common

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	gobig "math/big"
	"strconv"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

var BigOne = big.NewInt(1)
var GabiSystemParameters = gabi.DefaultSystemParameters[2048]

var AttributeTypes = []string{"FHIRL1", "sha256 of FHIR of FHIR Level1", "FHIRL2", "sha256 of FHIR Level2"}

type ProofSerialization struct {
	UnixTimeSeconds   int64
	DisclosureChoices []bool
	C                 *gobig.Int
	A                 *gobig.Int
	EResponse         *gobig.Int
	VResponse         *gobig.Int
	AResponses        []*gobig.Int
	ADisclosed        []*gobig.Int
}

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

func ComputeAttributes(attributeValues [][]byte) ([]*big.Int, error) {
	if len(AttributeTypes) != len(attributeValues) {
		return nil, errors.New("Amount of attribute values don't match amount of attribute types")
	}

	// Compute attributes
	attrs := make([]*big.Int, len(attributeValues))
	for i, val := range attributeValues {
		attrs[i] = new(big.Int)
		attrs[i].SetBytes(val)

		// Let the last bit distinguish empty vs. optional attributes
		attrs[i].Lsh(attrs[i], 1)             // attr <<= 1
		attrs[i].Add(attrs[i], big.NewInt(1)) // attr += 1
	}

	return attrs, nil
}

func CalculateTimeBasedChallenge(unixTimeSeconds int64) *big.Int {
	// Calculate the challenge as the sha256sum of the decimal string representation
	// of  the given unix timestamp in seconds. Cut off to appropriate amount of bits
	timeBytes := []byte(strconv.FormatInt(unixTimeSeconds, 10))
	timeHash := sha256.Sum256(timeBytes)

	challengeByteSize := GabiSystemParameters.Lstatzk / 8
	return new(big.Int).SetBytes(timeHash[:challengeByteSize])
}

func DebugSerializableStruct(s interface{}) {
	str, _ := json.Marshal(s)
	fmt.Println(string(str))
}
