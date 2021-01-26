package main

import (
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

type secretKey struct {
	Key *big.Int
}

var clientCredentials []*gabi.Credential

func ClientStart() {
	clientSk := generateSecretKey()

	serverSession := IssuerNewSession()
	credBuilder, issuerProofNonce := issuanceProofBuilders(issuerPk, clientSk)

	builders := gabi.ProofBuilderList([]gabi.ProofBuilder{credBuilder})
	issueCommitmentMessage := &gabi.IssueCommitmentMessage{
		Proofs: builders.BuildProofList(contextOne, serverSession.nonce, false),
		Nonce2: issuerProofNonce,
	}

	ism := IssuerPostCommitments(serverSession.sessionId, issueCommitmentMessage)
	cred, err := constructCredentials(ism, credBuilder, serverSession.attributeValues)
	if err != nil {
		panic("Error while constructing credentials")
	}

	clientCredentials = append(clientCredentials, cred)
}

func generateSecretKey() *secretKey {
	return &secretKey{
		Key: randomBigInt(new(big.Int).Lsh(big.NewInt(1), uint(gabi.DefaultSystemParameters[2048].Lm))),
	}
}

func issuanceProofBuilders(issuerPk *gabi.PublicKey, clientSk *secretKey) (*gabi.CredentialBuilder, *big.Int) {
	issuerProofNonce := generateNonce()
	credBuilder := gabi.NewCredentialBuilder(issuerPk, contextOne, clientSk.Key, issuerProofNonce, []int{})

	return credBuilder, issuerProofNonce
}

func constructCredentials(ism *gabi.IssueSignatureMessage, credBuilder *gabi.CredentialBuilder, attributeValues []string) (*gabi.Credential, error) {
	attributeInts, err := computeAttributes(attributeValues)
	if err != nil {
		return nil, err
	}

	cred, err := credBuilder.ConstructCredential(ism, attributeInts)
	if err != nil {
		return nil, err
	}

	return cred, nil
}