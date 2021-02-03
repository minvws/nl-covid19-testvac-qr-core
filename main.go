package main


import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"

	"github.com/minvws/nl-covid19-coronatester-ctcl-core/holder"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/issuer"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/verifier"
	"github.com/privacybydesign/gabi"
)
// SHA256(example-fhir-nl.bin)= 67409d726c4213eabe52bd6ac5a8c4624f601c0421541facb6ee49ebb0d867a4
const fileFhir = "example-fhir-nl.bin"

// SHA256(example-fhir-cz.bin)= f38dc38f61c78d6b80c4b8af18fdf6b78fd5dd68c6f0d4878d21e9f8363f9f0b
// const fileFhir = "example-fhir-cz.bin"

func main() {
	showFHIRExample()
}

func showFHIRExample() {
	fmt.Println("Testing issuer/holder/verifier packages:")

	fmt.Println("1) generate a new public key for the issuer")
	issuerPk, _ := gabi.NewPublicKeyFromXML(issuerPkXml)

        // Major cheat - we fill out this value; as current IRMA code does not
        // actually propagate what is currently in the XML; as it assume that these
        // public keys are subordinate to some sort of suitably annotated master xml.
        issuerPk.Issuer="<NL Public Health demo authority>"

	fmt.Printf("    Issuer is: %v \n", issuerPk.Issuer)

	fmt.Println("2) generate a holder key")
	holderSk := holder.GenerateHolderSk()
	fmt.Printf("    Holder is: %v \n", holderSk.String())

	fmt.Println("3) generate issuer nonce for this holder; and create the credential.")
	issuerNonce := issuer.GenerateIssuerNonce()
	credBuilder, icm := holder.CreateCommitment(issuerPk, issuerNonce, holderSk)

	fmt.Printf("   reading in the FHIR record (%v)\n", fileFhir)
	fhir, err := ioutil.ReadFile(fileFhir)
	if err != nil {
		fmt.Println(err)
	}

	rec := sha256.New()
	rec.Write([]byte(fhir))
        crc := rec.Sum(nil)
	crcHex := hex.EncodeToString(crc)

	fmt.Printf("    read in %d bytes of FHIR record\n",len(fhir))
	fmt.Printf("    FHIR record checksum: %v", crcHex)

        // attributeValues := [][]byte{fhir, []byte(crcHex)}
        attributeValues := [][]byte{fhir, []byte(crc)}
	ism := issuer.Issue(issuerPkXml, issuerSkXml, issuerNonce, attributeValues, icm)

	cred, err := holder.CreateCredential(credBuilder, ism, attributeValues)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("    sign and issue.")

	fmt.Printf("4) Citizen (Holder) gets the issuer its public key (%v) to check the signature.\n", issuerPk.Issuer)

	fmt.Println("5) Citizen (Holder) now goes into the wild")
	count := 5
	for i := 0; i < count; i++ {
		fmt.Printf("\n")
		fmt.Printf("    * An Encounter happens!\n")
		fmt.Printf("       Citizen generate a unique/new QR code and holds it up.\n")

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

		fmt.Printf("       Sha256 of the QR code is: %x\n", qr.Sum(nil))

		fmt.Printf("       Got proof size of %d bytes (i.e. the size of the Qr code)\n", len(proofAsn1))

		fmt.Printf("\n")

		fmt.Printf("      Verifier Scans the QR code to check proof against %v (public key of the issuer)\n", issuerPk.Issuer)

		verifiedValues, unixTimeSeconds, err := verifier.Verify(issuerPk, proofAsn1)

		rec := sha256.New()
		rec.Write([]byte(verifiedValues[0]))
		crc = rec.Sum(nil)
		crcHex = hex.EncodeToString(crc)

		val := []byte(verifiedValues[1])
		valHex := hex.EncodeToString(val)

		fmt.Printf("       FHIR Record Hash : %v\n", crcHex)
                fmt.Printf("       FHIR Stored Hash : %v\n", valHex)

		if err != nil {
			panic("Invalid proof")
		}
		if crcHex != valHex {
			panic("Valid proof, but crc mismatch")
		}

		fmt.Printf("      Valid proof for time %d:\n", unixTimeSeconds)
	}
}
