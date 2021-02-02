# CoronaTester CTCL

This is a proof of concept for creating a qr code system for proving that one has had a vaccination record(FHIR). 

#### Description
The aim for this project is to be able to show the whole process of how the proposed system might work. There are three main individuals: issuer, holder, and verifier. 
- The issuer is a medical institute that has provided the vaccine and has been certificated by a ministry to hand out vaccination certificates.    
- The holder is an individual who has been vaccinated. 
- The verifier is an individual who would like to check that the holder has been vaccinated. 

There is already a standard medical message for immunization in HL7 (both v3 CDA and FHIR) which can be re-used also for COVID-19 purposes. We use the work that was done in [nl-eHealth-experimental](https://github.com/minvws/nl-eHealth-experimental/tree/master/examples/who-smartvacc) repository to produce a FHIR record that has been encoded via protobuf. We use a subset of the FHIR record that is in the draft version of the WHO requirements. 



### Goals

This project is a work in progress. Below if is high level overview of what has been done and what still is being worked on.

Done: 
- Unlinkability: User has a new qr code to present on every scan. Qr codes cannot be grouped to an individual.

- Fits in a QR, can be done offline for the _holder_

- Can contain FHIR(ish) data 
    - Have the FHIR data from the WHO minimal data sets  

Work In Progress:
- One can mask values 'at will'
- Multi-country example code
    - Generate a QR code from citizen in country A and scan by country B.


# To Run
To run this proof of concept code run the following command in the directory: 

`go run ./`

Example Output:
```
Testing issuer/holder/verifier packages:
Issuer is:
Holder is: 13892351912983104006807806281716141590342270061828377999447667110929743356782


An Encounter happens!
Citizen generate a QR code and holds it up.
Sha256 of the qr code is: 55baa7f5b66b0e2df0cc6fd01da15552c89d6677ae4efde7bec870ea6f441525
Got proof size of 1037 bytes

Verifier Scans the QR code to check proof!
Valid proof for time 1612271987:
FHIR Record Hash: f38dc38f61c78d6b80c4b8af18fdf6b78fd5dd68c6f0d4878d21e9f8363f9f0b
FHIR Stored Hash : f38dc38f61c78d6b80c4b8af18fdf6b78fd5dd68c6f0d4878d21e9f8363f9f0b


An Encounter happens!
Citizen generate a QR code and holds it up.
Sha256 of the qr code is: fc8a51a56a6498dce64f764dfeb4481d49f3e08b7ac413d292c06db1dbfb1838
Got proof size of 1040 bytes

Verifier Scans the QR code to check proof!
Valid proof for time 1612271987:
FHIR Record Hash: f38dc38f61c78d6b80c4b8af18fdf6b78fd5dd68c6f0d4878d21e9f8363f9f0b
FHIR Stored Hash : f38dc38f61c78d6b80c4b8af18fdf6b78fd5dd68c6f0d4878d21e9f8363f9f0b


An Encounter happens!
Citizen generate a QR code and holds it up.
Sha256 of the qr code is: 950dedfc067266f93c77b04b646de966c165b1973ce1b3f3bb9286f84309e681
Got proof size of 1039 bytes

Verifier Scans the QR code to check proof!
Valid proof for time 1612271987:
FHIR Record Hash: f38dc38f61c78d6b80c4b8af18fdf6b78fd5dd68c6f0d4878d21e9f8363f9f0b
FHIR Stored Hash : f38dc38f61c78d6b80c4b8af18fdf6b78fd5dd68c6f0d4878d21e9f8363f9f0b


An Encounter happens!
Citizen generate a QR code and holds it up.
Sha256 of the qr code is: 01ee3b2b2524fdbf5a2714a3e1362f743984f714851398c431e6896d0b41e1be
Got proof size of 1038 bytes

Verifier Scans the QR code to check proof!
Valid proof for time 1612271987:
FHIR Record Hash: f38dc38f61c78d6b80c4b8af18fdf6b78fd5dd68c6f0d4878d21e9f8363f9f0b
FHIR Stored Hash : f38dc38f61c78d6b80c4b8af18fdf6b78fd5dd68c6f0d4878d21e9f8363f9f0b


An Encounter happens!
Citizen generate a QR code and holds it up.
Sha256 of the qr code is: 3ba04f3bcec8504f94f6cb8cb6124222c0d462ed407d208b5cbb52f0355e4049
Got proof size of 1038 bytes

Verifier Scans the QR code to check proof!
Valid proof for time 1612271987:
FHIR Record Hash: f38dc38f61c78d6b80c4b8af18fdf6b78fd5dd68c6f0d4878d21e9f8363f9f0b
FHIR Stored Hash : f38dc38f61c78d6b80c4b8af18fdf6b78fd5dd68c6f0d4878d21e9f8363f9f0b
```