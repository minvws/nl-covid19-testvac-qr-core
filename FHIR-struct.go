package main

import "time"

type FHIRRecord struct {
	ResourceType string `json:"resourceType"`
	ID           string `json:"id"`
	Identifier   struct {
		System string `json:"system"`
		Value  string `json:"value"`
		Period struct {
			Start time.Time `json:"start"`
		} `json:"period"`
	} `json:"identifier"`
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Entry     []struct {
		FullURL             string `json:"fullUrl"`
		ResourceComposition struct {
			ResourceType string `json:"resourceType"`
			ID           string `json:"id"`
			Identifier   struct {
				System string `json:"system"`
				Value  string `json:"value"`
			} `json:"identifier"`
			Status string `json:"status"`
			Type   struct {
				Coding []struct {
					System  string `json:"system"`
					Code    string `json:"code"`
					Display string `json:"display"`
				} `json:"coding"`
			} `json:"type"`
			Subject struct {
				Reference string `json:"reference"`
			} `json:"subject"`
			Date   time.Time `json:"date"`
			Author []struct {
				Display string `json:"display"`
			} `json:"author"`
			Title           string `json:"title"`
			Confidentiality string `json:"confidentiality"`
			Attester        []struct {
				Mode  string    `json:"mode"`
				Time  time.Time `json:"time"`
				Party struct {
					Reference string `json:"reference"`
				} `json:"party"`
			} `json:"attester"`
			Custodian struct {
				Reference string `json:"reference"`
			} `json:"custodian"`
			Section []struct {
				Title string `json:"title"`
				Code  struct {
					Coding []struct {
						System  string `json:"system"`
						Code    string `json:"code"`
						Display string `json:"display"`
					} `json:"coding"`
				} `json:"code"`
				Entry []struct {
					Reference string `json:"reference"`
				} `json:"entry"`
			} `json:"section"`
		} `json:"resource,omitempty"`
		ResourcePatient struct {
			ResourceType string `json:"resourceType"`
			ID           string `json:"id"`
			Identifier   []struct {
				Type struct {
					Coding []struct {
						System string `json:"system"`
						Code   string `json:"code"`
					} `json:"coding"`
				} `json:"type,omitempty"`
				System string `json:"system"`
				Value  string `json:"value"`
			} `json:"identifier"`
			Name []struct {
				Family string   `json:"family"`
				Given  []string `json:"given"`
			} `json:"name"`
			BirthDate string `json:"birthDate"`
		} `json:"resource,omitempty"`
		ResourceImmunization struct {
			ResourceType string `json:"resourceType"`
			ID           string `json:"id"`
			Status       string `json:"status"`
			VaccineCode  struct {
				Coding []struct {
					System  string `json:"system"`
					Code    string `json:"code"`
					Display string `json:"display"`
				} `json:"coding"`
				Text string `json:"text"`
			} `json:"vaccineCode"`
			Patient struct {
				Reference string `json:"reference"`
			} `json:"patient"`
			OccurrenceDateTime string `json:"occurrenceDateTime"`
			Location           struct {
				Reference string `json:"reference"`
			} `json:"location"`
			Manufacturer struct {
				Display string `json:"display"`
			} `json:"manufacturer"`
			LotNumber string `json:"lotNumber"`
			Performer []struct {
				Actor struct {
					Display string `json:"display"`
				} `json:"actor"`
			} `json:"performer"`
			ProtocolApplied []struct {
				TargetDisease []struct {
					Coding []struct {
						System string `json:"system"`
						Code   string `json:"code"`
					} `json:"coding"`
				} `json:"targetDisease"`
				DoseNumberPositiveInt int    `json:"doseNumberPositiveInt"`
				SeriesDosesString     string `json:"seriesDosesString"`
			} `json:"protocolApplied"`
		} `json:"resource,omitempty"`
		ResourceOrganization struct {
			ResourceType string `json:"resourceType"`
			ID           string `json:"id"`
			Identifier   []struct {
				System string `json:"system"`
				Value  string `json:"value"`
			} `json:"identifier"`
			Name string `json:"name"`
		} `json:"resource,omitempty"`
		ResourceLocation struct {
			ResourceType string `json:"resourceType"`
			ID           string `json:"id"`
			Name         string `json:"name"`
			Address      struct {
				City    string `json:"city"`
				Country string `json:"country"`
			} `json:"address"`
		} `json:"resource,omitempty"`
	} `json:"entry"`
}
