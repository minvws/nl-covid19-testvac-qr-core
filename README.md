# CoronaTester CTCL

This is a proof of concept (PoC) for creating a QR code system for proving that one has had a valid vaccination record (FHIR, see https://fhir.org).

The core of this code is _also_ used to convey a negative test result in the CoronaCheck app pair currently being build in the Netherlands. For more information about that code base can be found in the repositories https://github.com/minvws/nl-covid19-coronacheck-app-coordination, https://github.com/minvws/nl-covid19-coronacheck-app-android, https://github.com/minvws/nl-covid19-coronacheck-app-ios.

Key features to demonstrate are

1. Show that it is possible to sign or otherwise make values shown (such as I was tested negative on Thursday) somewhat tamper resistent.
1. Data minimisation - show that it is possible to selectively disclose only certain fields (depending on context) -- whilst keeping things such as digital signatures intact.
1. Unlinkability - make it impossible (or hard) to use the data shared to track a holder (citizen) (e.g. by the verifier simply recording all signatures shown, or by the issuering hearing of validations).
1. Show that this can by largely done off-line; not requiring a connection by the holder.

The cryptographic technologies are based on Camenisch-Lysyanskaya signatures and Zero Knowledge Proofs in general, and those of Idemix / Identiy Mixer (and IRMA.app) in particular.

## Context

This PoC is part of a wider piece of work to map, assess and curtail the privacy and security risks associated with the use cases for a citizen being able to prove vaccination or the veracity of a negative test result. This is driven by the anticipated need for a COVID-19 proof of vaccination requirement internationally. Note that there is currently no national requirement for such proof.

In particular, the risks and mitigations are explored for both paper-based and digital versions of possible implementations for a proof of vaccination or negative test.

This document explores the realm of possible technical implementation options and the social and legal requirements that constrain which of the technical implementations may be chosen. As such, this interplay defines the envelope within which realistic solutions are likely to fit.

## Description

The aim for this project is to be able to show the whole process of how the proposed system might work. There are three main individuals: issuer, holder, and verifier. 
- The issuer is a medical institute that has provided the vaccine or negative test result, and has been certified by a government to hand out such certificates.    
- The holder is an individual who has been vaccinated or negatively tested. 
- The verifier is an individual or organization who would like to verify that the holder has been vaccinated or negatively tested.

There is already a standard medical message for immunization in HL7 (both v3 CDA and FHIR) which can be re-used also for COVID-19 purposes. We use the work that was done in [nl-eHealth-experimental](https://github.com/minvws/nl-eHealth-experimental/tree/master/examples/smartvac) repository to produce a FHIR record that has been encoded as a protobuf. We use a subset of the FHIR record that is in the draft version of the WHO requirements.

The records are signed with a Camenisch-Lysyanskaya signature, which allows the proof to be presented in an unlinkable way by means of a Zero Knowledge Proof.

### Goals

This project is a work in progress. Below if is high level overview of what has been done and what still is being worked on.

Done: 
- Unlinkability: The holder creates a new QR code to present on every scan. QR codes cannot be linked between usages, to the issuance event or to an individual, by the signature itself.

- Fits in a QR, can be done offline for the _holder_

- Can contain FHIR(ish) data 
    - Have the FHIR data from the WHO minimal data sets  

Work In Progress:
- One can mask values 'at will' (selective disclosure)
- Multi-country example code
    - Generate a QR code from citizen in country A and scan by country B.


# To Run
To run this proof of concept code run the following command in the directory: 

`go run ./`

Example Output:
```
Testing issuer/holder/verifier packages:
1) generate a new public key for the issuer
    Issuer is: <NL Public Health demo authority> 
2) generate a holder key
    Holder is: 30903407693653827065565507804231738797510415673574501887342270311011859500140 
3) generate issuer nonce for this holder; and create the credential.
    sign and issue.
4) Citizen (Holder) gets the issuer its public key (<NL Public Health demo authority>) to check the signature.
5) Citizen (Holder) now goes into the wild

    * An Encounter happens!
       Citizen selects the disclosure level (*Level 0*) for the Verifier
       Citizen generates a unique/new QR code and holds it up.
       The QR code contains: UO515 HFQYO+BO02MVQ$904HVU+6R4.... (5.5bit / QR alphanumeric mode encoded)
       Got proof size of 1378 bytes (i.e. the size of the QR code in bytes)

      Verifier Scans the QR code to check proof against <NL Public Health demo authority> (public key of the issuer)
       Valid proof (signature was correct) for time: 1612879359 (unix seconds since epoch)
       FHIR level Computed Hash : 58e01505581caa107821700293446ebcf55c298b34caa652451d510acdb60f9a
       FHIR level Stored Hash   : 58e01505581caa107821700293446ebcf55c298b34caa652451d510acdb60f9a
      so this record was not tampered with.

    * An Encounter happens!
       Citizen selects the disclosure level (*Level 0*) for the Verifier
       Citizen generates a unique/new QR code and holds it up.
       The QR code contains: H:0K5ZT-:0BC2HO/K2-GK4A%.OP+EH.... (5.5bit / QR alphanumeric mode encoded)
       Got proof size of 1378 bytes (i.e. the size of the QR code in bytes)

      Verifier Scans the QR code to check proof against <NL Public Health demo authority> (public key of the issuer)
       Valid proof (signature was correct) for time: 1612879359 (unix seconds since epoch)
       FHIR level Computed Hash : 58e01505581caa107821700293446ebcf55c298b34caa652451d510acdb60f9a
       FHIR level Stored Hash   : 58e01505581caa107821700293446ebcf55c298b34caa652451d510acdb60f9a
      so this record was not tampered with.

    * An Encounter happens!
       Citizen selects the disclosure level (*Level 1*) for the Verifier
       Citizen generates a unique/new QR code and holds it up.
       The QR code contains:  1TP**GBYES5HSTOUGR/L2394165EL.... (5.5bit / QR alphanumeric mode encoded)
       Got proof size of 1390 bytes (i.e. the size of the QR code in bytes)

      Verifier Scans the QR code to check proof against <NL Public Health demo authority> (public key of the issuer)
       Valid proof (signature was correct) for time: 1612879359 (unix seconds since epoch)
       FHIR level Computed Hash : d8c6278ce528602ef58a7accd3e68dfaf6fdda8609fe8e2d58982cae2eca8d46
       FHIR level Stored Hash   : d8c6278ce528602ef58a7accd3e68dfaf6fdda8609fe8e2d58982cae2eca8d46
      so this record was not tampered with.

    * An Encounter happens with a Border Guard!
       Citizen selects the disclosure level (*Level 2*) for the Verifier
       Citizen generate a unique/new QR code and holds it up.
       The QR code contains: 8..7-**:T3SQTHWZWR-1FQ2A+83/JH.... (5.5bit / QR alphanumeric mode encoded)
       Got proof size of 1399 bytes (i.e. the size of the QR code in bytes)

      Verifier Scans the QR code to check proof against <NL Public Health demo authority> (public key of the issuer)
       Valid proof (signature was correct) for time: 1612879359 (unix seconds since epoch)
       FHIR level Computed Hash : 5ccd2e0f0accc1ad0051b317bdf2d222f757e7fc443e4c8db202d242a7115569
       FHIR level Stored Hash   : 5ccd2e0f0accc1ad0051b317bdf2d222f757e7fc443e4c8db202d242a7115569
      so this record was not tampered with.
```
