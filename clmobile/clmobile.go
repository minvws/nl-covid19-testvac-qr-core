package clmobile

import (
	"encoding/json"
	"gitlab.com/confiks/ctcl/holder"
)

func GenerateHolderSk() []byte {
	holderSkMessageJson, err := json.Marshal(holder.GenerateHolderSk())
	if err != nil {
		panic("Could not serialize holder secret key")
	}

	return holderSkMessageJson
}

func CreateCommitmentMessage(cmmMsgJson []byte) []byte {
	cmmMsg := &holder.CreateCommitmentsMessage{}
	err := json.Unmarshal(cmmMsgJson, cmmMsg)
	if err != nil {
		panic("Could not unmarshal CreateCommitmentsMessage")
	}

	icm, err := holder.CreateCommitment(cmmMsg)
	if err != nil {
		panic("Could not create commitment")
	}

	icmJson, err := json.Marshal(icm)
	if err != nil {
		panic("Could not serialize IssueCommitmentMessage")
	}

	return icmJson
}

func CreateCredential(credMsgJson []byte) []byte {
	credMsg := &holder.CreateCredentialMessage{}
	err := json.Unmarshal(credMsgJson, credMsg)
	if err != nil {
		panic("Could not unmarshal CreateCredentialMessage")
	}

	cred, err := holder.CreateCredential(credMsg)
	if err != nil {
		panic("Could not create credential")
	}

	credJson, err := json.Marshal(cred)
	if err != nil {
		panic("Could not serialize credential")
	}

	return credJson
}

func DiscloseAll() {

}