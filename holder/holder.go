package holder

import (
	"encoding/asn1"
	"time"

	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-testvac-qr-core/common"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

func GenerateHolderSk() *big.Int {
	return common.RandomBigInt(common.GabiSystemParameters.Lm)
}

func CreateCommitment(issuerPk *gabi.PublicKey, issuerNonce, holderSk *big.Int) (*gabi.CredentialBuilder, *gabi.IssueCommitmentMessage) {
	credBuilder, icm := createCommitments(issuerPk, issuerNonce, holderSk)
	return credBuilder, icm
}

func CreateCredential(credBuilder *gabi.CredentialBuilder, ism *gabi.IssueSignatureMessage, attributeValues [][]byte) (*gabi.Credential, error) {
	cred, err := constructCredential(ism, credBuilder, attributeValues)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not construct credential", 0)
	}

	return cred, nil
}

func DiscloseAll(cred *gabi.Credential, challenge *big.Int) ([]byte, error) {
	return Disclose(cred, maximumDisclosureChoices(cred), challenge)
}

func DiscloseLevel0WithTime(cred *gabi.Credential) ([]byte, error) {
	return DiscloseWithTime(cred, level0DisclosureChoices(cred))
}

func level0DisclosureChoices(cred *gabi.Credential) []bool {
	choices := make([]bool, len(cred.Attributes)-1)
	for i, _ := range choices {
		if i == 0 || i == 1 {
			choices[i] = true
		} else {
			choices[i] = false
		}
	}

	return choices
}

func DiscloseLevel1WithTime(cred *gabi.Credential) ([]byte, error) {
	return DiscloseWithTime(cred, level1DisclosureChoices(cred))
}

func level1DisclosureChoices(cred *gabi.Credential) []bool {
	choices := make([]bool, len(cred.Attributes)-1)
	for i, _ := range choices {
		if i == 2 || i == 3 {
			choices[i] = true
		} else {
			choices[i] = false
		}
	}

	return choices
}

func DiscloseLevel2WithTime(cred *gabi.Credential) ([]byte, error) {
	return DiscloseWithTime(cred, level2DisclosureChoices(cred))
}

func level2DisclosureChoices(cred *gabi.Credential) []bool {
	choices := make([]bool, len(cred.Attributes)-1)
	for i, _ := range choices {
		if i == 4 || i == 5 {
			choices[i] = true
		} else {
			choices[i] = false
		}
	}

	return choices
}

func DiscloseAllWithTime(cred *gabi.Credential) ([]byte, error) {
	return DiscloseWithTime(cred, maximumDisclosureChoices(cred))
}

func maximumDisclosureChoices(cred *gabi.Credential) []bool {
	choices := make([]bool, len(cred.Attributes)-1)
	for i, _ := range choices {
		choices[i] = true
	}

	return choices
}

func DiscloseWithTime(cred *gabi.Credential, disclosureChoices []bool) ([]byte, error) {
	return disclose(cred, disclosureChoices, nil)
}

func Disclose(cred *gabi.Credential, disclosureChoices []bool, challenge *big.Int) ([]byte, error) {
	if challenge == nil {
		return nil, errors.Errorf("No challenge was provided")
	}

	return disclose(cred, disclosureChoices, challenge)
}

func disclose(cred *gabi.Credential, disclosureChoices []bool, challenge *big.Int) ([]byte, error) {
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

	// If no challenge is provided, use a time-based 'challenge', and
	// save the time in the serialization of the proof
	ps := common.ProofSerialization{}
	if challenge == nil {
		ps.UnixTimeSeconds = time.Now().Unix()
		challenge = common.CalculateTimeBasedChallenge(ps.UnixTimeSeconds)
	}

	// Build proof
	var dpbs gabi.ProofBuilderList
	dpb, err := cred.CreateDisclosureProofBuilder(disclosedIndices, false)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Failed to create disclosure proof builder", 0)
	}

	dpbs = append(dpbs, dpb)

	proofList := dpbs.BuildProofList(common.BigOne, challenge, false)
	if len(proofList) != 1 {
		return nil, errors.Errorf("Invalid amount of proofs")
	}

	proof := proofList[0].(*gabi.ProofD)

	// Serialize proof
	ps.DisclosureChoices = disclosureChoices
	ps.C = proof.C.Go()
	ps.A = proof.A.Go()
	ps.EResponse = proof.EResponse.Go()
	ps.VResponse = proof.VResponse.Go()

	for i, disclosed := range disclosureChoices {
		if disclosed {
			ps.ADisclosed = append(ps.ADisclosed, proof.ADisclosed[i].Go())
		} else {
			ps.AResponses = append(ps.AResponses, proof.AResponses[i].Go())
		}
	}

	proofAsn1, err := asn1.Marshal(ps)
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

func constructCredential(ism *gabi.IssueSignatureMessage, credBuilder *gabi.CredentialBuilder, attributeValues [][]byte) (*gabi.Credential, error) {
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
