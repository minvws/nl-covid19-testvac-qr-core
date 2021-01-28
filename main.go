package main

import (
	"fmt"
	"gitlab.com/confiks/ctcl/holder"
	"gitlab.com/confiks/ctcl/issuer"
	"gitlab.com/confiks/ctcl/verifier"
)

func main() {
	holderSkMessage := holder.GenerateHolderSk()

	issuerNonce := issuer.GenerateIssuerNonce()

	cmmMsg := &holder.CreateCommitmentsMessage{
		IssuerPkXml: issuerPkXml,
		IssuerNonce: issuerNonce,
		HolderSk: holderSkMessage.Key,
	}
	icm, _ := holder.CreateCommitment(cmmMsg)

	attributeValues := []string{"foo", "bar"}
	ism := issuer.Issue(issuerPkXml, issuerSkXml, issuerNonce, attributeValues, icm)

	credMsg := &holder.CreateCredentialMessage{
		HolderSk: holderSkMessage.Key,
		IssueSignatureMessage: ism,
		AttributeValues: attributeValues,
	}
	cred, _ := holder.CreateCredential(credMsg)

	proofAsn1, _ := holder.DiscloseAll(cred)
	fmt.Printf("Got proof size of %d bytes\n", len(proofAsn1))

	verifyMessage := &verifier.VerifyMessage{
		IssuerPkXml: issuerPkXml,
		ProofAsn1: proofAsn1,
	}

	verifiedValues, unixTimeSeconds, err := verifier.Verify(verifyMessage)
	if err != nil {
		fmt.Println("Invalid proof")
	} else {
		fmt.Printf("Valid proof for time %d:\n", unixTimeSeconds)
		for k, v := range verifiedValues {
			fmt.Printf("%s: %s\n", k, *v)
		}
	}
}

