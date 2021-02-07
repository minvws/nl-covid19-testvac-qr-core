package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
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

	// fhir, err := ioutil.ReadFile("Vaccination-FHIR-Bundle - GC.bin")
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Printf("    read in %d of FHIR record\n", len(fhir))

	///////
	// Do Enc or Level1
	fhirl1, err := ioutil.ReadFile("Vaccination-FHIR-Bundle - GC.1.bin")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("    read in %d of FHIR record level 1\n", len(fhirl1))

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // here 2048 is the number of bits for RSA
	publicKey := privateKey.PublicKey
	encryptedMessageL1 := RSA_OAEP_Encrypt(fhirl1, publicKey)

	sha256_ekl1 := sha256.New()
	sha256_ekl1.Write(encryptedMessageL1)

	fmt.Printf("    Encrypted FHIR record level 1\n")
	fmt.Printf("    	Private key: %v\n", privateKey)
	fmt.Printf("    	Public key: %v\n", publicKey)
	fmt.Printf("    	sha256 is: %v\n", hex.EncodeToString(sha256_ekl1.Sum(nil)))

	// Do Enc or Level2
	fhirl2, err := ioutil.ReadFile("Vaccination-FHIR-Bundle - GC.2.bin")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("    read in %d of FHIR record level 2\n", len(fhirl2))

	privateKey, err = rsa.GenerateKey(rand.Reader, 2048) // here 2048 is the number of bits for RSA
	publicKey = privateKey.PublicKey
	encryptedMessageL2 := RSA_OAEP_Encrypt(fhirl2, publicKey)

	sha256_ekl2 := sha256.New()
	sha256_ekl2.Write(encryptedMessageL1)

	fmt.Printf("    Encrypted FHIR record level 2\n")
	fmt.Printf("    	Private key: %v\n", privateKey)
	fmt.Printf("    	Public key: %v\n", publicKey)
	fmt.Printf("    	sha256 is: %v\n", hex.EncodeToString(sha256_ekl2.Sum(nil)))

	////

	attributeValues := [][]byte{encryptedMessageL1, sha256_ekl1.Sum(nil), encryptedMessageL2, sha256_ekl2.Sum(nil)}
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
		if err != nil {
			fmt.Println("Invalid proof")
		} else {
			fmt.Printf("       Valid proof for time %d:\n", unixTimeSeconds)
			rec1 := sha256.New()
			rec1.Write([]byte(verifiedValues[0]))
			fmt.Printf("       FHIR level1 Record Hash : %v\n", hex.EncodeToString(rec1.Sum(nil)))
			fmt.Printf("       FHIR level1 Stored Hash : %v\n", verifiedValues[1])
			fmt.Printf("      so this record was not tamped with.\n")

			rec2 := sha256.New()
			rec2.Write([]byte(verifiedValues[0]))
			fmt.Printf("       FHIR level2 Record Hash : %v\n", hex.EncodeToString(rec2.Sum(nil)))
			fmt.Printf("       FHIR level2 Stored Hash : %v\n", verifiedValues[1])
			fmt.Printf("      so this record was not tamped with.\n")
		}
	}
}

//RSA_OAEP_Encrypt :
func RSA_OAEP_Encrypt(secretMessage []byte, key rsa.PublicKey) []byte {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &key, secretMessage, label)
	if err != nil {
		panic(err.Error())
	}
	return ciphertext
}
