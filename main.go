package main

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"

	"github.com/minvws/nl-covid19-coronatester-ctcl-core/holder"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/issuer"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/verifier"
	"github.com/privacybydesign/gabi"
)

func main() {
	showFHIRExample()
}

func showFHIRExample() {
	fmt.Println("Testing issuer/holder/verifier packages:")

	issuerPk, _ := gabi.NewPublicKeyFromXML(issuerPkXml)
	fmt.Printf("Issuer is: %v \n", issuerPk.Issuer)

	holderSk := holder.GenerateHolderSk()
	fmt.Printf("Holder is: %v \n", holderSk.String())

	issuerNonce := issuer.GenerateIssuerNonce()
	credBuilder, icm := holder.CreateCommitment(issuerPk, issuerNonce, holderSk)

	fhir, err := ioutil.ReadFile("Vaccination-FHIR-Bundle - GC.bin")
	if err != nil {
		fmt.Println(err)
	}

	attributeValues := [][]byte{[]byte("foo"), []byte("bar"), fhir}
	ism := issuer.Issue(issuerPkXml, issuerSkXml, issuerNonce, attributeValues, icm)

	cred, err := holder.CreateCredential(credBuilder, ism, attributeValues)
	if err != nil {
		panic(err.Error())
	}

	count := 5
	for i := 0; i < count; i++ {
		fmt.Printf("\n---\n\nAn Encounter happens!\n")
		fmt.Printf("Citizen generate a QR code and holds it up.\n")

		proofAsn1, err := holder.DiscloseAllWithTime(cred)
		if err != nil {
			panic(err.Error())
		}

		qr := sha256.New()
		qr.Write(proofAsn1)

		// err1 := ioutil.WriteFile("qr.bin", proofAsn1, 0644)
		// if err1 != nil {
		// 	panic(err)
		// }

		fmt.Printf("Sha256 of the qr code is: %x\n", qr.Sum(nil))

		fmt.Printf("Got proof size of %d bytes\n", len(proofAsn1))

		verifiedValues, unixTimeSeconds, err := verifier.Verify(issuerPk, proofAsn1)
		if err != nil {
			fmt.Println("Invalid proof")
		} else {
			fmt.Printf("Valid proof for time %d:\n", unixTimeSeconds)
			for k, v := range verifiedValues {
				fmt.Printf("%d: %v\n", k, v)
			}
		}
	}
}