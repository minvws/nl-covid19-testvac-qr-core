package holder

import (
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"gitlab.com/confiks/ctcl/issuer"
	"gitlab.com/confiks/ctcl/common"
)

type secretKey struct {
	Key *big.Int
}

var credentials []*gabi.Credential

func Start() {
	clientSk := generateSecretKey()

	issuerPk, err := gabi.NewPublicKeyFromXML(common.IssuerPkXml)
	if err != nil {
		panic("Error loading issuer public key")
	}

	serverSession := issuer.NewSession()
	credBuilder, issuerProofNonce := issuanceProofBuilders(issuerPk, clientSk)

	builders := gabi.ProofBuilderList([]gabi.ProofBuilder{credBuilder})
	issueCommitmentMessage := &gabi.IssueCommitmentMessage{
		Proofs: builders.BuildProofList(common.ContextOne, serverSession.Nonce, false),
		Nonce2: issuerProofNonce,
	}

	ism := issuer.PostCommitments(serverSession.SessionId, issueCommitmentMessage)
	cred, err := constructCredentials(ism, credBuilder, serverSession.AttributeValues)
	if err != nil {
		panic("Error while constructing credentials")
	}

	credentials = append(credentials, cred)
}

func generateSecretKey() *secretKey {
	return &secretKey{
		Key: common.RandomBigInt(new(big.Int).Lsh(big.NewInt(1), uint(gabi.DefaultSystemParameters[2048].Lm))),
	}
}

func issuanceProofBuilders(issuerPk *gabi.PublicKey, clientSk *secretKey) (*gabi.CredentialBuilder, *big.Int) {
	issuerProofNonce := common.GenerateNonce()
	credBuilder := gabi.NewCredentialBuilder(issuerPk, common.ContextOne, clientSk.Key, issuerProofNonce, []int{})

	return credBuilder, issuerProofNonce
}

func constructCredentials(ism *gabi.IssueSignatureMessage, credBuilder *gabi.CredentialBuilder, attributeValues []string) (*gabi.Credential, error) {
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