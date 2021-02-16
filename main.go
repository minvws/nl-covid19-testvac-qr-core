package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	gobig "math/big"

	"github.com/minvws/nl-covid19-coronatester-ctcl-core/holder"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/issuer"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/verifier"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	qrcode "github.com/skip2/go-qrcode"
)

// SHA256(example-fhir-nl.bin)= 67409d726c4213eabe52bd6ac5a8c4624f601c0421541facb6ee49ebb0d867a4
const fileFhir = "example-fhir-nl.bin"

// SHA256(example-fhir-cz.bin)= f38dc38f61c78d6b80c4b8af18fdf6b78fd5dd68c6f0d4878d21e9f8363f9f0b
// const fileFhir = "example-fhir-cz.bin"

func main() {
	showFHIRExample()
}

var qrCharset = []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:")
var qrCharsetLen = gobig.NewInt(45)

func qrEncode(input []byte) []byte {
	estOutputLen := int(float64(len(input))*1.4568) + 1
	output := make([]byte, 0, estOutputLen)

	divident, remainder := new(gobig.Int), new(gobig.Int)
	divident.SetBytes(input)

	for len(divident.Bits()) != 0 {
		divident, remainder = divident.QuoRem(divident, qrCharsetLen, remainder)
		output = append(output, qrCharset[remainder.Int64()])
	}

	return output
}

// showFHIRExample :
func showFHIRExample() {
	// Country 1
	issuerPk, credBuilder, icm, issuerNonce := issuerCreation(issuerPkXml, "NL")

	cred := holderGen(issuerPk, credBuilder, icm, issuerNonce)

	encounter(cred, 0, 2, issuerPk)
	encounter(cred, 1, 1, issuerPk)
	encounter(cred, 2, 1, issuerPk)

	// Country 2
	issuerPkDE, credBuilderDE, icmDE, issuerNonceDE := issuerCreation(issuerPkXml, "DE")

	credDE := holderGen(issuerPkDE, credBuilderDE, icmDE, issuerNonceDE)

	encounter(credDE, 0, 2, issuerPkDE)
	encounter(credDE, 1, 1, issuerPkDE)
	encounter(credDE, 2, 1, issuerPkDE)
}

//issuerCreation : creates a new public key for the issuer from the main key
//returns the issuers public key,
func issuerCreation(inputKey string, inputCountry string) (*gabi.PublicKey, *gabi.CredentialBuilder, *gabi.IssueCommitmentMessage, *big.Int) {
	fmt.Println("Testing issuer/holder/verifier packages:")

	fmt.Println("1) generate a new public key for the issuer who is " + inputCountry)
	issuerPk, _ := gabi.NewPublicKeyFromXML(inputKey)

	// Major cheat - we fill out this value; as current IRMA code does not
	// actually propagate what is currently in the XML; as it assume that these
	// public keys are subordinate to some sort of suitably annotated master xml.
	issuerPk.Issuer = "<" + inputCountry + " Public Health demo authority>"

	fmt.Printf("    Issuer is: %v \n", issuerPk.Issuer)

	fmt.Println("2) generate a holder key " + inputCountry)
	holderSk := holder.GenerateHolderSk()
	fmt.Printf("    Holder is: %v \n", holderSk.String())

	fmt.Println("3) generate issuer nonce for this holder; and create the credential.")
	issuerNonce := issuer.GenerateIssuerNonce()
	credBuilder, icm := holder.CreateCommitment(issuerPk, issuerNonce, holderSk)

	return issuerPk, credBuilder, icm, issuerNonce
}

func holderGen(issuerPk *gabi.PublicKey, credBuilder *gabi.CredentialBuilder, icm *gabi.IssueCommitmentMessage, issuerNonce *big.Int) *gabi.Credential {
	///////
	// Level 0
	// pubKey, privateKeyl1 := verifierGeneratesPrivateKey()
	// encryptedMessageL1, sha256_ekl1 := generateEncQRPayload("Vaccination-FHIR-Bundle - GC.1.bin", pubKey)

	VBL0, err := ioutil.ReadFile("Vaccination-FHIR-Bundle - GC.0.bin")
	if err != nil {
		fmt.Println("File reading error", err)
	}

	sha256_VBL0 := sha256.New()
	sha256_VBL0.Write(VBL0)

	///////
	// Level 1
	// pubKey, privateKeyl1 := verifierGeneratesPrivateKey()
	// encryptedMessageL1, sha256_ekl1 := generateEncQRPayload("Vaccination-FHIR-Bundle - GC.1.bin", pubKey)

	VBL1, err := ioutil.ReadFile("Vaccination-FHIR-Bundle - GC.1.bin")
	if err != nil {
		fmt.Println("File reading error", err)
	}

	sha256_VBL1 := sha256.New()
	sha256_VBL1.Write(VBL1)

	///////
	// Level 2
	// pubKey, privateKeyl1 := verifierGeneratesPrivateKey()
	// encryptedMessageL1, sha256_ekl1 := generateEncQRPayload("Vaccination-FHIR-Bundle - GC.1.bin", pubKey)

	VBL2, err := ioutil.ReadFile("Vaccination-FHIR-Bundle - GC.2.bin")
	if err != nil {
		fmt.Println("File reading error", err)
	}

	sha256_VBL2 := sha256.New()
	sha256_VBL2.Write(VBL2)

	//
	attributeValues := [][]byte{VBL0, []byte(hex.EncodeToString(sha256_VBL0.Sum(nil))), VBL1, []byte(hex.EncodeToString(sha256_VBL1.Sum(nil))), VBL2, []byte(hex.EncodeToString(sha256_VBL2.Sum(nil)))}
	ism := issuer.Issue(issuerPkXml, issuerSkXml, issuerNonce, attributeValues, icm)

	cred, err := holder.CreateCredential(credBuilder, ism, attributeValues)
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("    sign and issue.")

	fmt.Printf("4) Citizen (Holder) gets the issuer its public key (%v) to check the signature.\n", issuerPk.Issuer)

	fmt.Println("5) Citizen (Holder) now goes into the wild")
	return cred
}

func encounter(cred *gabi.Credential, level int, numbEnc int, issuerPk *gabi.PublicKey) {
	for i := 0; i < numbEnc; i++ {
		fmt.Printf("\n")
		fmt.Printf("    * An Encounter happens!\n")

		fmt.Printf("       Citizen selects the disclosion level (*Level " + fmt.Sprint(level) + "*) for the Verifier\n")

		fmt.Printf("       Citizen generates a unique/new QR code and holds it up.\n")

		var proofAsn1 []byte
		if level == 1 {
			proofAsn1, _ = holder.DiscloseLevel1WithTime(cred)
		} else if level == 2 {
			proofAsn1, _ = holder.DiscloseLevel2WithTime(cred)
		} else {
			proofAsn1, _ = holder.DiscloseLevel0WithTime(cred)
		}

		proofAsnstring := string(qrEncode(proofAsn1))
		err := qrcode.WriteFile(proofAsnstring, qrcode.Medium, 512, "qr_level"+fmt.Sprint(level)+".png")
		if err != nil {
			panic(err.Error())
		}

		qr := sha256.New()
		qr.Write(proofAsn1)

		fmt.Printf("       The QR code contains: %v.... (5.5bit / QR alphanumeric mode encoded)\n", proofAsnstring[:30])

		fmt.Printf("       Got proof size of %d bytes (i.e. the size of the QR code in bytes)\n", len(proofAsn1))

		fmt.Printf("\n")

		fmt.Printf("      Verifier Scans the QR code to check proof against %v (public key of the issuer)\n", issuerPk.Issuer)

		verifiedValues, unixTimeSeconds, err := verifier.Verify(issuerPk, proofAsn1)
		if err != nil {
			fmt.Println("Invalid proof")
		} else {
			fmt.Printf("       Valid proof for time %d:\n", unixTimeSeconds)
			rec1 := sha256.New()
			rec1.Write([]byte(verifiedValues[level*2])) // 0,2,4
			fmt.Printf("       FHIR level Computed Hash : %v\n", hex.EncodeToString(rec1.Sum(nil)))
			fmt.Printf("       FHIR level Stored Hash : %v\n", verifiedValues[level*2+1]) // 1,3,5
			fmt.Printf("      so this record was not tampered with.\n")

		}
	}
}
