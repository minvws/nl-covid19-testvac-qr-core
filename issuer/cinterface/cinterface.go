package main

import "C"
import (
	"encoding/json"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/common"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/issuer"
)

// export GetIssuingNonce
func GenerateIssuerNonceB64() *C.Char {
	issuerNonceB64, err := json.Marshal(issuer.GenerateIssuerNonce())
	if err != nil {
		panic("Could not serialize issuer nonce")
	}

	return C.CString(issuerNonceB64)
}

// export Issue
func Issue(issuerPkXml, issuerSkXml, issuerNonceB64, commitmentsJson string, attributeValues []string) *C.Char {
	issuerNonce := new(big.Int)
	err := issuerNonce.UnmarshalJSON([]byte(issuerNonceB64))
	if err != nil {
		panic("Could not deserialize issuerNonce")
	}

	if issuerNonce.BitLen() != int(common.GabiSystemParameters.Lstatzk) {
		panic("Invalid length for issuerNonce")
	}

	// Commitments
	var commitments *gabi.IssueCommitmentMessage
	err = json.Unmarshal([]byte(commitmentsJson), commitments)
	if err != nil {
		panic("Could not deserialize commitments")
	}

	sig := issuer.Issue(issuerPkXml, issuerSkXml, issuerNonce, attributeValues, commitments)
	return C.CString(json.Marshal(sig))
}
