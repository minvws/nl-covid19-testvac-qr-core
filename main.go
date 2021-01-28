package main

import (
	"fmt"
	"github.com/privacybydesign/gabi"
	"gitlab.com/confiks/ctcl/holder"
	"gitlab.com/confiks/ctcl/issuer"
	"gitlab.com/confiks/ctcl/verifier"
)

func main() {
	issuerPk, _ := gabi.NewPublicKeyFromXML(issuerPkXml)
	holderSk := holder.GenerateHolderSk()

	issuerNonce := issuer.GenerateIssuerNonce()
	credBuilder, icm := holder.CreateCommitment(issuerPk, issuerNonce, holderSk)

	attributeValues := []string{"foo", "bar"}
	ism := issuer.Issue(issuerPkXml, issuerSkXml, issuerNonce, attributeValues, icm)

	cred, err := holder.CreateCredential(credBuilder, ism, attributeValues)
	if err != nil {
		panic(err.Error())
	}

	proofAsn1, err := holder.DiscloseAllWithTime(cred)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("Got proof size of %d bytes\n", len(proofAsn1))

	verifiedValues, unixTimeSeconds, err := verifier.Verify(issuerPk, proofAsn1)
	if err != nil {
		fmt.Println("Invalid proof")
	} else {
		fmt.Printf("Valid proof for time %d:\n", unixTimeSeconds)
		for k, v := range verifiedValues {
			fmt.Printf("%s: %s\n", k, *v)
		}
	}
}

