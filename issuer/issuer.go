package issuer

import (
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"gitlab.com/confiks/ctcl/common"
)

type IssuanceSession struct {
	SessionId       int
	Nonce           *big.Int
	AttributeValues []string
}

var issuanceSessions = map[int]*IssuanceSession{}

var sessionIdCounter = 0
func getSessionId() int {
	sessionIdCounter++
	return sessionIdCounter
}

var issuerPk *gabi.PublicKey = nil
var issuerSk *gabi.PrivateKey = nil

func LoadKeys() {
	var err error
	issuerPk, err = gabi.NewPublicKeyFromXML(common.IssuerPkXml)
	issuerSk, err = gabi.NewPrivateKeyFromXML(issuerSkXml, false)
	if err != nil {
		panic("Error loading issuer keys")
	}
}

func NewSession() *IssuanceSession {
	session := &IssuanceSession{
		SessionId:       getSessionId(),
		Nonce:           common.GenerateNonce(),
		AttributeValues: []string{"foo", "bar"},
	}

	issuanceSessions[session.SessionId] = session
	return session
}

func PostCommitments(sessionId int, commitments *gabi.IssueCommitmentMessage) *gabi.IssueSignatureMessage {
	issuanceSession, ok := issuanceSessions[sessionId]
	if !ok {
		panic("Invalid session")
	}

	// handleSessionCommitments -> handlePostCommitments
	if len(commitments.Proofs) != 1 {
		panic("Incorrect amount of proofs")
	}

	// Compute attribute values
	issuer := gabi.NewIssuer(issuerSk, issuerPk, common.ContextOne)
	proof, ok := commitments.Proofs[0].(*gabi.ProofU)
	if !ok {
		panic("Received invalid issuance commitment")
	}

	attributeInts, err := common.ComputeAttributes(issuanceSession.AttributeValues)
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