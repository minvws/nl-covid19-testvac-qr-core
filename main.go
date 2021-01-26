package main

import (
	"gitlab.com/confiks/ctcl/holder"
	"gitlab.com/confiks/ctcl/issuer"
)

func main() {
	holderSkMessage := holder.GenerateHolderSk()

	issuerNonce := issuer.GetIssuerNonce()

	cmmMsg := &holder.CreateCommitmentsMessage{
		IssuerPkXml: issuerPkXml,
		IssuerNonce: issuerNonce,
		HolderSk: holderSkMessage.Key,
	}
	icm := holder.CreateCommitment(cmmMsg)

	attributeValues := []string{"foo", "bar"}
	ism := issuer.Issue(issuerPkXml, issuerSkXml, issuerNonce, attributeValues, icm)

	credMsg := &holder.CreateCredentialMessage{
		HolderSk: holderSkMessage.Key,
		IssueSignatureMessage: ism,
		AttributeValues: attributeValues,

	}
	holder.CreateCredential(credMsg)
}

