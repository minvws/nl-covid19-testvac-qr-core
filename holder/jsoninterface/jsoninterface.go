package jsoninterface

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

	icm := holder.CreateCommitment(cmmMsg)

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

	cred := holder.CreateCredential(credMsg)

	credJson, err := json.Marshal(cred)
	if err != nil {
		panic("Could not serialize credential")
	}

	return credJson
}