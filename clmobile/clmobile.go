package clmobile

import (
	"encoding/json"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"gitlab.com/confiks/ctcl/holder"
)

func GenerateHolderSk() ([]byte, string) {
	holderSkJson, err := json.Marshal(holder.GenerateHolderSk())
	if err != nil {
		return nil, errors.Errorf("Could not serialize holder secret key").Error()
	}

	return holderSkJson, ""
}

type CreateCommitmentsMessage struct {
	IssuerPkXml string
	IssuerNonce *big.Int
	HolderSk    *big.Int
}

// TODO: Handle state properly
var dirtyHack *gabi.CredentialBuilder

func CreateCommitmentMessage(holderSkJson, issuerPkXml, issuerNonceJson []byte) ([]byte, string) {
	var holderSk *big.Int
	err := json.Unmarshal(holderSkJson, holderSk)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not unmarshal holder sk", 0).Error()
	}

	issuerPk, err := gabi.NewPublicKeyFromXML(string(issuerPkXml))
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not unmarshal issuer public key", 0).Error()
	}

	var issuerNonce *big.Int
	err = json.Unmarshal(issuerNonceJson, issuerNonce)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not unmarshal issuer nonce", 0).Error()
	}

	credBuilder, icm := holder.CreateCommitment(issuerPk, issuerNonce, holderSk)
	dirtyHack = credBuilder // FIXME

	icmJson, err := json.Marshal(icm)
	if err != nil {
		panic("Could not marshal IssueCommitmentMessage")
	}

	return icmJson, ""
}

type CreateCredentialMessage struct {
	IssueSignatureMessage *gabi.IssueSignatureMessage
	AttributeValues       []string
}

func CreateCredential(holderSkJson, ccmJson []byte) ([]byte, string) {
	var holderSk *big.Int
	err := json.Unmarshal(holderSkJson, holderSk)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not unmarshal holder sk", 0).Error()
	}

	ccm := &CreateCredentialMessage{}
	err = json.Unmarshal(ccmJson, ccm)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not unmarshal CreateCredentialMessage", 0).Error()
	}

	credBuilder := dirtyHack // FIXME

	cred, err := holder.CreateCredential(credBuilder, ccm.IssueSignatureMessage, ccm.AttributeValues)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not create credential", 0).Error()
	}

	credJson, err := json.Marshal(cred)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not marshal credential", 0).Error()
	}

	return credJson, ""
}

func DiscloseAllWithTime(credJson []byte) ([]byte, string) {
	var cred *gabi.Credential
	err := json.Unmarshal(credJson, cred)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not unmarshal credential", 0).Error()
	}

	proofAsn1, err := holder.DiscloseAllWithTime(cred)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not create proof", 0).Error()
	}

	return proofAsn1, ""
}
