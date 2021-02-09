package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	gobig "math/big"

	"github.com/minvws/nl-covid19-coronatester-ctcl-core/holder"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/issuer"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/verifier"
	"github.com/privacybydesign/gabi"
	qrcode "github.com/skip2/go-qrcode"
)

// SHA256(example-fhir-nl.bin)= 67409d726c4213eabe52bd6ac5a8c4624f601c0421541facb6ee49ebb0d867a4
const fileFhir = "example-fhir-nl.bin"

// SHA256(example-fhir-cz.bin)= f38dc38f61c78d6b80c4b8af18fdf6b78fd5dd68c6f0d4878d21e9f8363f9f0b
// const fileFhir = "example-fhir-cz.bin"

func main() {
	// record := reciveFHIRJSON()
	// genPB(record)
	showFHIRExample()
}

func reciveFHIRJSON() FHIRRecord {
	// read file
	data, err := ioutil.ReadFile("./Vaccination-FHIR-Bundle-GC.json")
	if err != nil {
		fmt.Print(err)
	}

	// json data
	var obj FHIRRecord

	// unmarshall it
	err = json.Unmarshal(data, &obj)
	if err != nil {
		fmt.Println("error:", err)
	}

	return obj
}

// func genPB(entry FHIRRecord) {
// 	// m, err := structpb.NewValue(entry)
// 	// if err != nil {
// 	// 	fmt.Println("error:", err)
// 	// }

// 	// val := SmartVaccCert1{}
// 	data, err := ioutil.ReadFile("./Vaccination-FHIR-Bundle-GC.json")
// 	if err != nil {
// 		fmt.Print(err)
// 	}

// 	out := protojson.UnmarshalOptions{
// 		AllowPartial: true,
// 	}
// 	out.Unmarshal(data, &val)
// 	fmt.Printf("Out: %v", val)
// }

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

func showFHIRExample() {
	fmt.Println("Testing issuer/holder/verifier packages:")

	fmt.Println("1) generate a new public key for the issuer")
	issuerPk, _ := gabi.NewPublicKeyFromXML(issuerPkXml)

	// Major cheat - we fill out this value; as current IRMA code does not
	// actually propagate what is currently in the XML; as it assume that these
	// public keys are subordinate to some sort of suitably annotated master xml.
	issuerPk.Issuer = "<NL Public Health demo authority>"

	fmt.Printf("    Issuer is: %v \n", issuerPk.Issuer)

	fmt.Println("2) generate a holder key")
	holderSk := holder.GenerateHolderSk()
	fmt.Printf("    Holder is: %v \n", holderSk.String())

	fmt.Println("3) generate issuer nonce for this holder; and create the credential.")
	issuerNonce := issuer.GenerateIssuerNonce()
	credBuilder, icm := holder.CreateCommitment(issuerPk, issuerNonce, holderSk)

	///////
	// Level 0
	// pubKey, privateKeyl1 := verifierGeneratesPrivateKey()
	// encryptedMessageL1, sha256_ekl1 := generateEncQRPayload("Vaccination-FHIR-Bundle - GC.1.bin", pubKey)

	VBL0, err := ioutil.ReadFile("Vaccination-FHIR-Bundle - GC.0.bin")
	if err != nil {
		fmt.Println("File reading error", err)
		return
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
		return
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
		return
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

	//Level 0 Encounter
	for i := 0; i < 2; i++ {
		fmt.Printf("\n")
		fmt.Printf("    * An Encounter happens!\n")

		fmt.Printf("       Citizen selects the disclosion level (*Level 0*) for the Verifier\n")

		fmt.Printf("       Citizen generates a unique/new QR code and holds it up.\n")

		proofAsn1, err := holder.DiscloseLevel0WithTime(cred)
		if err != nil {
			panic(err.Error())
		}

		proofAsn1string := string(qrEncode(proofAsn1))
		err = qrcode.WriteFile(proofAsn1string, qrcode.Medium, 512, "qr_level1.png")
		if err != nil {
			panic(err.Error())
		}

		qr := sha256.New()
		qr.Write(proofAsn1)

		fmt.Printf("       The QR code contains: %v.... (5.5bit / QR alphanumeric mode encoded)\n", proofAsn1string[:30])

		fmt.Printf("       Got proof size of %d bytes (i.e. the size of the QR code in bytes)\n", len(proofAsn1))

		fmt.Printf("\n")

		fmt.Printf("      Verifier Scans the QR code to check proof against %v (public key of the issuer)\n", issuerPk.Issuer)

		verifiedValues, unixTimeSeconds, err := verifier.Verify(issuerPk, proofAsn1)
		if err != nil {
			fmt.Println("Invalid proof")
		} else {
			fmt.Printf("       Valid proof for time %d:\n", unixTimeSeconds)
			rec1 := sha256.New()
			rec1.Write([]byte(verifiedValues[0]))
			fmt.Printf("       FHIR level Computed Hash : %v\n", hex.EncodeToString(rec1.Sum(nil)))
			fmt.Printf("       FHIR level Stored Hash : %v\n", verifiedValues[1])
			fmt.Printf("      so this record was not tampered with.\n")

			// RSA_OAEP_Decrypt([]byte(verifiedValues[0]), privateKeyl1)

		}
	}

	//Level 1 Encounter
	for i := 0; i < 1; i++ {
		fmt.Printf("\n")
		fmt.Printf("    * An Encounter happens!\n")

		fmt.Printf("       Citizen selects the disclosion level (*Level 1*) for the Verifier\n")

		fmt.Printf("       Citizen generates a unique/new QR code and holds it up.\n")

		proofAsn1, err := holder.DiscloseLevel1WithTime(cred)
		if err != nil {
			panic(err.Error())
		}

		proofAsn1string := string(qrEncode(proofAsn1))
		err = qrcode.WriteFile(proofAsn1string, qrcode.Medium, 512, "qr_level1.png")
		if err != nil {
			panic(err.Error())
		}

		qr := sha256.New()
		qr.Write(proofAsn1)

		fmt.Printf("       The QR code contains: %v.... (5.5bit / QR alphanumeric mode encoded)\n", proofAsn1string[:30])

		fmt.Printf("       Got proof size of %d bytes (i.e. the size of the QR code in bytes)\n", len(proofAsn1))

		fmt.Printf("\n")

		fmt.Printf("      Verifier Scans the QR code to check proof against %v (public key of the issuer)\n", issuerPk.Issuer)

		verifiedValues, unixTimeSeconds, err := verifier.Verify(issuerPk, proofAsn1)
		if err != nil {
			fmt.Println("Invalid proof")
		} else {
			fmt.Printf("       Valid proof for time %d:\n", unixTimeSeconds)
			rec1 := sha256.New()
			rec1.Write([]byte(verifiedValues[2]))
			fmt.Printf("       FHIR level Computed Hash : %v\n", hex.EncodeToString(rec1.Sum(nil)))
			fmt.Printf("       FHIR level Stored Hash : %v\n", verifiedValues[3])
			fmt.Printf("      so this record was not tampered with.\n")

			// RSA_OAEP_Decrypt([]byte(verifiedValues[0]), privateKeyl1)

		}
	}

	//Level 2 Encounter
	for i := 0; i < 1; i++ {
		fmt.Printf("\n")
		fmt.Printf("    * An Encounter happens with a Boarder Guard!\n")

		fmt.Printf("       Citizen selects the disclosion level (*Level 2*) for the Verifier\n")

		fmt.Printf("       Citizen generate a unique/new QR code and holds it up.\n")

		proofAsn1, err := holder.DiscloseLevel2WithTime(cred)
		if err != nil {
			panic(err.Error())
		}

		proofAsn1string := string(qrEncode(proofAsn1))
		err = qrcode.WriteFile(proofAsn1string, qrcode.Medium, 512, "qr_level2.png")
		if err != nil {
			panic(err.Error())
		}

		qr := sha256.New()
		qr.Write(proofAsn1)

		fmt.Printf("       The QR code contains: %v.... (5.5bit / QR alphanumeric mode encoded)\n", proofAsn1string[:30])

		fmt.Printf("       Got proof size of %d bytes (i.e. the size of the QR code in bytes)\n", len(proofAsn1))

		fmt.Printf("\n")

		fmt.Printf("      Verifier Scans the QR code to check proof against %v (public key of the issuer)\n", issuerPk.Issuer)

		verifiedValues, unixTimeSeconds, err := verifier.Verify(issuerPk, proofAsn1)
		if err != nil {
			fmt.Println("Invalid proof")
		} else {
			fmt.Printf("       Valid proof for time %d:\n", unixTimeSeconds)
			rec1 := sha256.New()
			rec1.Write([]byte(verifiedValues[4]))
			fmt.Printf("       FHIR level Computed Hash : %v\n", hex.EncodeToString(rec1.Sum(nil)))
			fmt.Printf("       FHIR level Stored Hash : %v\n", verifiedValues[5])
			fmt.Printf("      so this record was not tampered with.\n")

			// RSA_OAEP_Decrypt([]byte(verifiedValues[0]), privateKeyl1)

		}
	}

}
