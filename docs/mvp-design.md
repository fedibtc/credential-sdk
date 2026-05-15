## Scope

Eng:

- Support in-person verification flow between two users
- Generate a privacy-preserving proof of trust after verification
- Allow revocation or decay of trust signals over time

## Use Cases

“Fedi Blue Check”… and all the things a blue check could be used:

- federations
- users
- spaces
- etc.

Per Fedi’s [blog post](https://www.fedi.xyz/blog/digital-trust-without-surrender-or-surveillance) the primary use case at this point is Nostr identity verification and trustworthiness indication.

---

## Engineering Approach

## MVP Flows

Fedi Masters/Knights around the world need to begin issuing credentials.

For the purposes of the initial MVP, users need to be able to ISSUE, HOLD, and VERIFY trust credentials/attestations.

The eng scope of this project includes the following:

- Define the **protocol** for trust credentials, including the cryptographic protocol, credentialing scheme, transport protocol.
- Design & build the software to issue, store, and (maybe) verify credentials.
- Think through the process for attaching credentials to a Nostr event.
- Think through the process for importing credentials into other systems that might leverage them.

## Actors

In the context of verifiable credential schemes, there are three main actors that comprise the system:

- The credential **issuer** is a trusted entity that creates credentials/attestations.
  - ex: Fedi/Master/Knight, reputable organization X, user-configured trusted entity X.
- The credential **holder** is the recipient of credentials from the issuer.
  - ex: Trusted community leader deemed trustworthy in a privacy-preserving manner.
- The credential **verifier** is the user who reads/checks the authenticity of credentials.
  - ex: Other users online that need to discover and interact with the trusted party (holder).

Here is this “triangle of trust” showed in the form of a diagram:

## Blinding/Cryptography Methodology

- Issuer Bundle
  Issuer signs issuance bundle with root identity keys (e.g. nsec). The bundle includes the pubkey used for issuing credentials (e.g. RSA 2048), the identity pubkey for the issuer (e.g. npub), and the location for posting credential revocations which MUST be scanned by verifiers in the process of credential verification.
  Before a verifier can accept credentials from a given issuer, they must receive and verify the issuer’s “Issuer Bundle”, containing the details of their trusted set
  ```json
  // ex. Issuer Bundle
  {
  	"issuer": {
  	  // identity pubkey for issuer (like npub)
  	  "issuer_id_pubkey": "issuer-id-pubkey",
  		// Keys used for issuing partially-blinded credentials (e.g. RSA 2048)
  		"issuance_key": "rsa-pubkey-for-credential-issuance",
  		// Locations where revocations may be posted by the issuer.
  		"revocation": [{
  		  "protocol": "rev-protocl" // e.g. nostr, https, etc.
  		  "location": "https://..." // e.g. relays like wss://.., https://...
  		}]
  	},
  	"proof": {
  	  // issuer_id_pubkey signs over issuer bundle.
  		"signature": "issuer-signature"
  	}
  }
  ```
- Verifiable Credentials

  ```jsx
  // ex. Partially Blind Verifiable Credential schema

  {
  	"credential": {
  		// Visible to issuer during issuance.
  		// Determines anonymity set
  		"info": {
  			"schema": "base64url(SHA256(canonical_schema_without_digest))",
  			// Issuer root id key (e.g. npub)
  		  "issuer_id_pubkey": "issuer-id-pubkey",
  		  // "What is the issuer claiming about the holder?"
  		  // score as decided by issuer
  	    "score": 7,
  	  },
  	  // hidden from issuer during signing
  	  "blind_msg": "anonymous-holder-public-key",
    },
    "proof": {
      // signed by "issuance_key" in preloaded issuer bundle.
      // signature is over whole "credential" object
      // THIS is the final version stored by the holder, so yes this signature
      // is UNblinded
      "signature": "RSA-signature", // RSAPBSSA-SHA384-PSS-Randomized?
    }
  }
  ```

- Schema Definition
  - Credential includes schema digest and the public committed data.
  - Optionally publish Schema Definition as a separate Nostr note
  ```jsx
  // ex. Schema Definition for a generic trust score
  {
    "schema": {
      "id": "fedi-trust-score",
      "version": "1.0.0",
      // "canonicalization": "JCS",
      // digest includes "id" and "version:
      "digest": "base64url(SHA256(canonical_schema_without_digest))",
      "fields": {
        "info" : {
          "schema": "string",
          "issuer_id_pubkey": "string",
          "score": "number"
        }
        "blind_msg": "string"
      }
    }
  },
  ```
- Revocation
  Revocation can only happen in response to publicly attributable online activity that is associated with the holder’s pubkey which was signed (for example, abusing the blue check mark). Due to the privacy preserving nature of the blinded signature scheme described above, we have no real-world link between the individual and the public key that was credentialed.
  The “Revocation” object should be published by the issuer to each of the revocations locations included in the issuer bundle.
  ```json
  // Revocation object
  {
    "revocation": {
      "credential_digest": "SHA256(canonical_credential)"
    },
    "proof": {
      "issuer_id_pubkey": "id-public-key",
      // RSAPBSSA-SHA384-PSS-Randomized?
      "signature": "partially-blinded-signature"
    }
  }
  ```

## App Architecture

How is this built? Not a new mobile app. Preferably not a standalone web app. But rather a mini-app. And we need 3 functionalities:

- Issuer can generate keypair, import secret key. Issuer can scan QR codes of holders (holders’ blinded public keys). Issuer can then attach a score (some arbitrary metadata) and sign together over the holder’s blinded public key + visible score. Issuer can then expose the signature as a QR code itself that the holder can then scan. **Note that issuer will first need to present their own pubkey to holder so holder can use issuer’s pubkey to blind their own pubkey.**
- Holder can generate keypair, import secret key, export public or secret key. Holder can present QR code which represents their blinded public key. Holder can scan QR code representing the signature from the issuer. Holder saves this credential (comprised of unblinded signature, holder’s public key, score) as well as issuer’s public key. And holder should also be able to export this credential + issuer’s public key.
- Verifier should be able to scan holder’s credential, and affirm that the credential is valid according to the Fedi public key that it was signed by, and that the public key is part of Fedi’s trusted keys. (For future, verifier should also be able to add other public keys for verifying holders’ credentials).

We looked at BBS+ and partially blinded schemes, and decided to go with the latter, and in particular that partially blinded RSA signatures ([RFC 9474](https://datatracker.ietf.org/doc/rfc9474/) + [draft-irtf-cfrg-partially-blind-rsa-02](https://www.ietf.org/archive/id/draft-irtf-cfrg-partially-blind-rsa-02.html)). Build it in preferred language with preferred library (rust equivalent crate is `blind-rsa-signatures` and the `pbrsa` module within it).

#### Web App (Mini-app) Architecture:

- Single web app with 3 tabs: Issuer, Holder, Verifier
  - Intended to be used as a Fedi mod.
- Keys are generated / stored in the webapp (browser storage)
- Communication via sharing QR Codes (see flows below)

#### Flows

- Issuer
  - Keys (both identity keys & RSA/issuance keys)
    - Generate secret keys (nsec & RSA 2048)
    - Import secret key (nsec and/or issuance keys)
    - Create issuer bundle
    - export issuer bundle
  - Schema definition
    - Define/publish new schema definition containing blinded & unblinded fields
    - load previously-published schema definition
  - credential issuance
    - Select credential schema ^^
    - Manually fill-in unblinded fields (score, autofill issuer pubkey)
    - Share pbRSA public key to holder via QR code
      - (holder blinds their own pubkey using the shared pbRSA pubkey)
    - scan a QR code from holder containing BLINDED data
    - Preview & sign credential. (pbRSA)
    - Present signed credential back to holder. (QR)
  - history
    - View/export list of all issued credentials.
      - Check / Show “revoked”?
    - Publish revocation message
- Holder
  - Keys (nostr)
    - Generate secret key
    - Import secret key
    - export public or secret key
  - Credential Issuance
    - Scan QR code from issuer containing pbrsa pubkey
    - perform blinding operation over own pubkey (using the scanned pbrsa pubkey)
    - present QR containing blinded pubkey
    - Scan qr code from issuer with signed credential.
  - history
    - View list of all received credentials.
      - Check / Show “revoked”?
    - Export credentials (for later use in applications e.g., nostr publishing)
- Verifier
  - Load issuer bundles (from nostr, manually, etc.)
  - Import / select credentials
  - Perform verification operation, show “success”/”failure”
    - check if issuer is known
    - check list of revocation locations for existence of credential digest
    - verify signatures/schema
