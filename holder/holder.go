package holder

import (
	"encoding/asn1"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"gitlab.com/confiks/ctcl/common"
	gobig "math/big"
)

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
	HolderSk    *big.Int
}

// TODO: We either need to modify gabi to export credBuilder's vPrime,
//   so we don't have to maintain state here, or keep state here (properly).
var dirtyHack *gabi.CredentialBuilder

func CreateCommitment(cmmMsg *CreateCommitmentsMessage) (*gabi.IssueCommitmentMessage, error) {
	issuerPk, err := gabi.NewPublicKeyFromXML(cmmMsg.IssuerPkXml)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not unmarshal issuer public key", 0)
	}

	// Create commitments
	credBuilder, icm := createCommitments(issuerPk, cmmMsg.IssuerNonce, cmmMsg.HolderSk)

	// FIXME
	dirtyHack = credBuilder

	return icm, nil
}

type CreateCredentialMessage struct {
	HolderSk              *big.Int
	IssueSignatureMessage *gabi.IssueSignatureMessage
	AttributeValues       []string
}

func CreateCredential(credMsg *CreateCredentialMessage) (*gabi.Credential, error) {
	// FIXME
	credBuilder := dirtyHack

	cred, err := constructCredential(credMsg.IssueSignatureMessage, credBuilder, credMsg.AttributeValues)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not construct credential", 0)
	}

	return cred, nil
}

func DiscloseAll(cred *gabi.Credential) ([]byte, error) {
	disclosureChoices := make([]bool, len(cred.Attributes) - 1)
	for i, _ := range disclosureChoices {
		disclosureChoices[i] = true
	}

	//return Disclose(cred, disclosureChoices, time.Now().Unix())
	return Disclose(cred, disclosureChoices, 12345678)
}

func Disclose(cred *gabi.Credential, disclosureChoices []bool, unixTimeSeconds int64) ([]byte, error) {
	// The first attribute (which is the secret key) can never be disclosed
	disclosureChoices = append([]bool{false}, disclosureChoices...)
	if len(disclosureChoices) != len(cred.Attributes) {
		return nil, errors.Errorf("Invalid amount of disclosure choices")
	}

	// Calculate indexes of disclosed attributes
	var disclosedIndices []int
	for i, disclosed := range disclosureChoices {
		if disclosed {
			disclosedIndices = append(disclosedIndices, i)
		}
	}

	// Build proof
	var dpbs gabi.ProofBuilderList
	dpb, err := cred.CreateDisclosureProofBuilder(disclosedIndices, false)
	if err != nil {
		return nil, errors.WrapPrefix(err,"Failed to create disclosure proof builder", 0)
	}

	dpbs = append(dpbs, dpb)

	timeBasedChallenge := common.CalculateTimeBasedChallenge(unixTimeSeconds)
	proofList := dpbs.BuildProofList(common.BigOne, timeBasedChallenge, false)
	if len(proofList) != 1 {
		return nil, errors.Errorf("Invalid amount of proofs")
	}

	proof := proofList[0].(*gabi.ProofD)

	// Serialize proof
	var aResponses, aDisclosed []*gobig.Int
	for i, disclosed := range disclosureChoices {
		if disclosed {
			aDisclosed = append(aDisclosed, proof.ADisclosed[i].Go())
		} else {
			aResponses = append(aResponses, proof.AResponses[i].Go())
		}
	}

	proofAsn1, err := asn1.Marshal(common.ProofSerialization{
		UnixTimeSeconds:   unixTimeSeconds,
		DisclosureChoices: disclosureChoices,
		C:                 proof.C.Go(),
		A:                 proof.A.Go(),
		EResponse:         proof.EResponse.Go(),
		VResponse:         proof.VResponse.Go(),
		AResponses:        aResponses,
		ADisclosed:        aDisclosed,
	})
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not ASN1 marshal proof", 0)
	}

	return proofAsn1, nil
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
