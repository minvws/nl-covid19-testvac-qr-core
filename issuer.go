package main

import (
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

type issuanceSession struct {
	sessionId int
	nonce *big.Int
	attributeValues []string
}

var issuanceSessions = map[int]*issuanceSession{}

var sessionIdCounter = 0
func getSessionId() int {
	sessionIdCounter++
	return sessionIdCounter
}

var issuerPk *gabi.PublicKey = nil
var issuerSk *gabi.PrivateKey = nil

func IssuerNewSession() *issuanceSession {
	session := &issuanceSession{
		sessionId: getSessionId(),
		nonce: generateNonce(),
		attributeValues: []string{"foo", "bar"},
	}

	issuanceSessions[session.sessionId] = session
	return session
}

func IssuerPostCommitments(sessionId int, commitments *gabi.IssueCommitmentMessage) *gabi.IssueSignatureMessage {
	issuanceSession, ok := issuanceSessions[sessionId]
	if !ok {
		panic("Invalid session")
	}

	// handleSessionCommitments -> handlePostCommitments
	if len(commitments.Proofs) != 1 {
		panic("Incorrect amount of proofs")
	}

	// Compute attribute values
	issuer := gabi.NewIssuer(issuerSk, issuerPk, contextOne)
	proof, ok := commitments.Proofs[0].(*gabi.ProofU)
	if !ok {
		panic("Received invalid issuance commitment")
	}

	attributeInts, err := computeAttributes(issuanceSession.attributeValues)
	if err != nil {
		panic("Error during computing attributes: " + err.Error())
	}

	// Compute CL signatures
	sig, err := issuer.IssueSignature(proof.U, attributeInts, nil, commitments.Nonce2, []int{})
	if err != nil {
		panic("Issuance failed: " + err.Error())
	}
	return sig
}