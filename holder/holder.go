package holder

import (
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"gitlab.com/confiks/ctcl/common"
)

var credentials []*gabi.Credential

type HolderSkMessage struct {
	Key *big.Int
}

func GenerateHolderSk() *HolderSkMessage {
	return &HolderSkMessage{
		Key: common.RandomBigInt(common.GabiSystemParameters.Lm),
	}
}

type CreateCommitmentsMessage struct {
	IssuerPkXml string
	IssuerNonce *big.Int
	HolderSk *big.Int
}

// TODO: We either need to modify gabi to export credBuilder's vPrime,
//   so we don't have to maintain state here, or keep state here (properly).
var dirtyHack *gabi.CredentialBuilder

func CreateCommitment(cmmMsg *CreateCommitmentsMessage) *gabi.IssueCommitmentMessage {
	issuerPk, err := gabi.NewPublicKeyFromXML(cmmMsg.IssuerPkXml)
	if err != nil {
		panic("Could not unmarshal issuer public key")
	}

	// Create commitments
	credBuilder, icm := createCommitments(issuerPk, cmmMsg.IssuerNonce, cmmMsg.HolderSk)

	// FIXME
	dirtyHack = credBuilder

	return icm
}

type CreateCredentialMessage struct {
	HolderSk *big.Int
	IssueSignatureMessage *gabi.IssueSignatureMessage
	AttributeValues []string
}

func CreateCredential(credMsg *CreateCredentialMessage) *gabi.Credential {
	// FIXME
	credBuilder := dirtyHack

	cred, err := constructCredential(credMsg.IssueSignatureMessage, credBuilder, credMsg.AttributeValues)
	if err != nil {
		panic("Error while constructing credentials")
	}

	return cred
}

func Disclose() {
	// doSession -> getProof -> client.Proofs ->
	// client.ProofBuilders
	// BuildProofList


}

func createCommitments(issuerPk *gabi.PublicKey, issuerNonce, holderSk *big.Int) (*gabi.CredentialBuilder, *gabi.IssueCommitmentMessage) {
	credBuilder, holderNonce := issuanceProofBuilders(issuerPk, holderSk)

	builders := gabi.ProofBuilderList([]gabi.ProofBuilder{credBuilder})
	icm := &gabi.IssueCommitmentMessage{
		Proofs: builders.BuildProofList(common.BigOne, issuerNonce, false),
		Nonce2: holderNonce,
	}

	return credBuilder, icm
}

func issuanceProofBuilders(issuerPk *gabi.PublicKey, holderSk *big.Int) (*gabi.CredentialBuilder, *big.Int) {
	holderNonce := common.GenerateNonce()
	credBuilder := gabi.NewCredentialBuilder(issuerPk, common.BigOne, holderSk, holderNonce, []int{})

	return credBuilder, holderNonce
}

func constructCredential(ism *gabi.IssueSignatureMessage, credBuilder *gabi.CredentialBuilder, attributeValues []string) (*gabi.Credential, error) {
	attributeInts, err := common.ComputeAttributes(attributeValues)
	if err != nil {
		return nil, err
	}

	cred, err := credBuilder.ConstructCredential(ism, attributeInts)
	if err != nil {
		return nil, err
	}

	return cred, nil
}