package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/minvws/nl-covid19-coronatester-ctcl-core/clmobile"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/holder"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/issuer"
	"github.com/minvws/nl-covid19-coronatester-ctcl-core/verifier"
	"github.com/privacybydesign/gabi"
)

func main() {
	// TODO: Move these test to proper tests
	testIssuerHolderVerifier()
	testClmobile()
	testExampleISM()
}

func testIssuerHolderVerifier() {
	fmt.Println("Testing issuer/holder/verifier packages:")

	issuerPk, _ := gabi.NewPublicKeyFromXML(issuerPkXml)
	fmt.Printf("Issuer is: %v \n", issuerPk.Issuer)

	holderSk := holder.GenerateHolderSk()
	fmt.Printf("Holder is: %v \n", holderSk.String())

	issuerNonce := issuer.GenerateIssuerNonce()
	credBuilder, icm := holder.CreateCommitment(issuerPk, issuerNonce, holderSk)

	attributeValues := [][]byte{[]byte("foo"), []byte("bar")}
	ism := issuer.Issue(issuerPkXml, issuerSkXml, issuerNonce, attributeValues, icm)

	cred, err := holder.CreateCredential(credBuilder, ism, attributeValues)
	if err != nil {
		panic(err.Error())
	}

	count := 5
	for i := 0; i < count; i++ {
		fmt.Printf("An Encounter happens!\n")
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
				fmt.Printf("%d: %s\n", k, v)
			}
		}
	}
}

func testClmobile() {
	fmt.Println("\nClmobile test:")

	r1 := clmobile.GenerateHolderSk()
	if r1.Error != "" {
		panic("Error in GenerateHolderSk: " + r1.Error)
	}

	issuerNonce := issuer.GenerateIssuerNonce()
	issuerNonceBase64, _ := issuerNonce.MarshalText()

	r2 := clmobile.CreateCommitmentMessage(r1.Value, []byte(issuerPkXml), issuerNonceBase64)
	if r2.Error != "" {
		panic("Error in CreateCommitmentMessage: " + r2.Error)
	}

	icm := new(gabi.IssueCommitmentMessage)
	err := json.Unmarshal(r2.Value, icm)
	if err != nil {
		panic("Error serializing ICM")
	}

	attributeValues := [][]byte{[]byte("foo"), []byte("bar")}
	ism := issuer.Issue(issuerPkXml, issuerSkXml, issuerNonce, attributeValues, icm)

	ccm := &clmobile.CreateCredentialMessage{
		IssueSignatureMessage: ism,
		AttributeValues:       attributeValues,
	}
	ccmJson, _ := json.Marshal(ccm)

	r3 := clmobile.CreateCredential(r1.Value, ccmJson)
	if r3.Error != "" {
		panic("Error creating credential:" + r3.Error)
	}

	r4 := clmobile.DiscloseAllWithTime([]byte(issuerPkXml), r3.Value)
	if r4.Error != "" {
		panic("Error disclosing credential: " + r4.Error)
	}

	r5 := clmobile.Verify([]byte(issuerPkXml), r4.Value)
	if r5.Error != "" {
		panic("Error verifying credential: " + r5.Error)
	}

	fmt.Printf("Valid proof for time %d:\n", r5.UnixTimeSeconds)
	for k, v := range r5.AttributeValues {
		fmt.Printf("%d: %s\n", k, v)
	}
}

func testExampleISM() {
	example := "{\"___debug\":{\"nonce\":\"4KnwQExYs11KPJr2MQh40Q==\",\"icm\":{\"n_2\":\"H8ZyGciQbxq8lI\\/ytZLI1A==\",\"combinedProofs\":[{\"U\":\"nbiauvF+TrxWU0fAeBmgfrzuLM4fouuqJaE3TMo4i4jbnR7EzUaJ2t+q3+69M2TL85S7diQvi\\/BrDuEemGpPfE7XaQSahkwpQ\\/AgKVkaVFdaAEIFdwwxyCHthK+NJ7liYYqGHGHBJbhIGQll97\\/iYE9i7SCqa7FhJBSNqAk7fpc\\/BSCmNYzk1KZAHSwzZP0ny4panqCbex2lzefMEt41Wj1lB2wgPw9TvykdaYsEIrRU9bh8r3qLprXpRaLoQAlJQT7viSGPy\\/iqo4kk8ST3qiCbBUP+kLtzOLzTKg1JVu5axr\\/lvUjkSq2QCWMH0XJv6TesWs+rD0TjSLKPDCq2mA==\",\"c\":\"DrFCbq6sjk8r6Mg70A10Aq1GICMb\\/tfXcBqrXKPKUp8=\",\"v_prime_response\":\"ubZgD7zeYT7F564dX09xW+W2GsH53MBEoeh48mUG45PHI+nyO6NiLbpJG2jjeIpzPyemaC3U7gDu+Ev4yVXQ0s42vnHv3V\\/VJ004NFJc7vE7nyvcAlFT+rMnLbjBTfd05GyXnzp2VrtvwwcumBUOl3SjkLhleo8Da6Z8mwDSQ\\/tsEmEvs9b428ZNS2X9fbR6tWt1m2OPt9piDvNP3HnEJLEjwZPe84\\/VV1IPrPQ+GL+fu4EFcSdK8dH8GeZiqsrClo34g5fNNAcGF3sy3uAqDKq27qydLjnYop9sRXcjaXSh9gSMuztXv83voFRU69FZ7Zr9yWx\\/UqjBw\\/pa2HBOz9oxcr9Re4fgjoPP8xNysb4KH8osN\\/VSSyYukG78n52A2tjIzZIMLGozQl0H34SEStxm7C7CCnAH20EST+AgDA8=\",\"s_response\":\"9vUo5ehedjeInA5hKqu2Cl0TVJiDLRJQpWFNhDyuMWTcmekz1qrPX+En0uPNbFXWBZz6v52tI38qBy8v+RAn0h1j4OPNrFdbts4=\"}]}},\"test_signatures\":[{\"uuid\":\"4e8c9d0a-41ba-4ff3-9366-e590daaafb69\",\"signature\":\"XbGj8hB74VeExY9balBLtQWZwBovJIdTVR19GAF0Z5yb5MSh\\/0+dB3VBR\\/zqxVaxQ+NzwuxZ5OHrmrq2OIz+DQ==\"},{\"uuid\":\"3dafabd7-cb77-40e6-aeb7-00c6c1c6af26\",\"signature\":\"OeR802JrGWrDl7cuEXNleXFkXiYVFGNPz69RhiCTHgv04KzcO9A6fYRD7pzKru6QanQOI3uBjUF00KxubnTKAQ==\"}],\"test_results\":[{\"uuid\":\"4e8c9d0a-41ba-4ff3-9366-e590daaafb69\",\"ism\":{\"proof\":{\"c\":\"6ACGc9ZtgJt8BCgnUC1\\/uti\\/CRyLgcmSckMaaJTnuDk=\",\"e_response\":\"EUTb+d0EfBVgAFDYvAanvwp3jHLkZQnPTlBZKNGPpGpA1rVK34yzk\\/cKOeNjraJwmiTQ5C6KKTawJQ0daev+aEtfFUEOkYZfoWwiqOD\\/ofw7pEB8h7wG7OS0PGQG26qgAaVz26q1j3Qip5os1zYn+iBU6lq5y8tr8po0a5kiBq1hxoFGK2p1ChkqczSdy0PE0+SNfw9F9esBjeNUYLKtkNiQlNVfBg6GqS4n9kaXGoeTrgAjoWLJbQGnu4JSLNgEH4le\\/oOPcRk8wiaKGVobnotjKDLWC0QOzHrPHYsVY+j8fM8M+YPUp8iuOSKanGX+rfgAib7RyaxOj92COl82YQ==\"},\"signature\":{\"A\":\"JVlmt78g3X90\\/1BuW9YYSeCDRULuWGvP8aPybgm7N7sNVRU1O4zc4F4dDa11mM59hCtu2tqy\\/B8Mn4F184B34KwAXoH1DUXEl0cb4k3Tu971erSLhHNN5h1RCPQmWDYWLUvgoj8gOq06GeoNc8JxRRE2ntef8\\/6HhbKaLDa3JeiD6MD0o5vML8q1Yi345JiLs59snDTkyOnHvnLT4L63mzsGC9IFZ7JpI6bpsQkrAEbLI+CBUElQuITQOjjW97Mp1C5ORQB\\/RxKdGKNUm8M1Rf4bi9q4XGIHBG6vYWg6tj23BTU6XU1veawxquJQE8GNlfKj4dHro6CiIH3qGhULPA==\",\"e\":\"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeMPo9hUgPYHSOh0aTJ9d\",\"v\":\"Cj8+6K83mucFHfbdee7rAwpnDiq7Sck6O0WVmXs6NGKU6DTln9Nh7pY9UVMIi5\\/ldfuTvhKBLC\\/GMAr6pjjQURYUNWEYCUNLO4UgwwBCqnQo5BdGANC5+UuSu9GU8f+hzLWzKouy5lUI3G5crYAqKCYs29b4rXYqyBmjDkAXaovqGNTN72hvbFaFzwqSLpKOKDGZKSsKbWB8waWg6NAsCdq5+tHR19BGTy5TJjL+6RgBZWJ2Ey+E54lHTCKlQ9WIzYh7d1U45ellhBATODU6fJscEaKSU1ijy0MOFTJ4DjzWUTFvJCsTaxQNrvBtYxSIb7F058opfSr3kPBj5jUFt3PqICMZUFWo3rL7B3HRpZVrGZxga49Mwx1aSoctIchhwd5Djzu8S4go6e5xxs4nbJNyrOy1B4ySER1JQ\\/c0yKQ+DhXYi2sQ9OHnKNci2mWP1SNW3LTLa3D\\/d\\/fg1IvmlCw=\",\"KeyshareP\":null}},\"attributes\":[\"e556ecd395a1\",\"1611694086\"],\"___test_type\":\"e556ecd395a1\",\"___date_taken\":1611694086,\"___issuer\":\"a0d81705-01af-4d9e-95bc-d11124e7fc63\",\"___result\":0},{\"uuid\":\"3dafabd7-cb77-40e6-aeb7-00c6c1c6af26\",\"ism\":{\"proof\":{\"c\":\"1D+WPzYYjEc9jtyEFC+7g+0XaSHzYGHef\\/lWHH1GpwA=\",\"e_response\":\"HNiRKOBZocK\\/BprysjwZiXsmCOS3NgLpZ1Q8Xphbsra4T\\/VoflLzjkQUXhx4sYXbfMbU6GSooqv\\/mMQl3f5UfhrvwIr6W4sHLzNYCWe6UVjNTAVdGDtvqDPaLa2eAFmgp6wrp2oAdTdu\\/2QwHOhY+\\/h6Qt5ydNCQJlV2H19ZjDYTHubPGsQwPjlDrx8TOKsFf7H1RprlDXDtk9lFvgneJLSCdljabC5a88PkoApkDRlE98jmN41bhrkkFfjGmprGtRZVHb9XIza\\/UIDEiQDD1Vaz7vc3ABjWc6QFpz6R3tBaAcUyAVhvNiCXO1mP+gY1LSD7apYcBTOlDdUOux+kLw==\"},\"signature\":{\"A\":\"D3yoXEMLep+\\/hnu9Ew5GoO32Y1w54umpVZGICrcc1Xmz0pjs6ZUNesL8iuOCmAtupfN4XVK8uN2DcO4Vg0NcrcyD3A9fRg9AHM9ceP2E4QLbzmiSXq7+Ffz9cdQyaVmkcVE81OLKbFfgSCJJxcxU7ryqDxqjsTKW83W60gEgwyHaZMTfF2PUUnOwlMgHrpagGOlX4hyuTGB2ucXIr2gJu4No2sTD0XZSB9tgxixPoX2Aki15WS7BARq6l9nEhxqNuOmcenl3xRzK5OjqLJgj5sTHYmDi1sgkPqMzm1OlA9IbHtGiAQtiqeBH2P37tf9uX6RSng2JiebZYSha+dTKXA==\",\"e\":\"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKNjUjDhPUQdMVrcAFkKN\",\"v\":\"CUW6aQpPwBmWk6dE1DtHbSnhJ4YT48MHzEyhL7YkMJIA8h9v0MZUMGabJ2hgV2I9\\/H1C7fshjzYXmZmHDgrrEbU3aicAldFDFc5fTGJuR8+p4e8TRU5on1Ath+LBvuqFVV+iH2ZPMyRKt\\/3HNs2vOJy3IYYYMANIVTackAENXLtA5vf+qQmwci73h9zW9cvB0NEBWX+w+RfFGDaOzMCqseYw8mylGy2pzWUOSJoRdv488Ujyj1Wbk85BGTGDN0mjm4KoIALfLGAsDEJ5XsXz2HIE4UEFEe0Gl1B6bTqxBapPJBWxhOuLQjwrz93OA0gTwI7bgRX9yx6JDxzZw8EISGe9cUYmvcweKFUgyC6+ByL6pOrYsSkQzJV1DW\\/PcV7dR\\/MncQgcUPvG8o7+p\\/1zLgTDDY\\/T1KvL6BYj1wA2vRsabQtVOIk47sxrC7EIizH9BvUO2jaQopUiLRaL3MZsR6Q=\",\"KeyshareP\":null}},\"attributes\":[\"0b775caa2149\",\"1611694206\"],\"___test_type\":\"0b775caa2149\",\"___date_taken\":1611694206,\"___issuer\":\"a0d81705-01af-4d9e-95bc-d11124e7fc63\",\"___result\":0}],\"test_types\":[{\"uuid\":\"e556ecd395a1\",\"name\":\"Quick Test\"},{\"uuid\":\"0b775caa2149\",\"name\":\"PCR\"}]}"
	ccm := new(clmobile.CreateCredentialMessage)

	err := json.Unmarshal([]byte(example), ccm)
	if err != nil {
		panic("Error unmarshaling example")
	}
}
