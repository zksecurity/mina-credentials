# Technical Specification for Mina Credentials

This document is a low-level technical specification for the Mina Credentials system.
It is intended as document for the accompanying codebase and implementators.
It does not include security proofs or motivations for the design choices,
see the RFC for such discussions.

# Metadata

Metadata SHOULD NOT be constrained during the creation of a credential.
Metadata MUST NOT be used to determine the validity of a credential or its issuer.
Metadata MUST only be used to present information about the credential in a human-readable way
inside wallets and other applications for easy identification and selection.
Metadata MUST NOT be used to make trust decisions.
Metadata MUST NOT be presented to the verifier during the presentation of a credential.

# Formats

## Mina Credential

A credential is a set of attributes and an owner:

```javascript
type AppAttributes = {
  [key: string]: Any, // any o1js type
}

type Attributes = {
  owner: Field,       // credential owners identifier (references a DID or public key)
  meta: Field,        // hash of arbitrary metadata
  app: AppAttributes, // application-specific attributes (e.g. name, age, etc.)
}
```

Is is stored along with metadata and the version of the credential:

```javascript
type WitnessIssuance =
  | { type: "simple",
      issuerPK: PublicKey,
      issuerSignature: Signature,
    }
  | { type: "recursive",
      credVK: VerificationKey,
      credIdent: Field,
      credProof: Proof,
    }
```

```javascript
type StoredCredential = {
  version: "v0",
  witness: Witness,
  metadata: Metadata,
  credential: Credential,
}
```

```javascript
type OwnerIdentity = {
  | { type: "public-key",
      pk: PublicKey,
    }
  | { type: "did",
      did: Field,
    }
}

type OwnerWitness =
  | { type: "public-key",
      pk: PublicKey,  // public key of the owner
      sig: Signature, // signature under the owners public key
    }
  | { type: "did"
      did: Field,     // a hash of the DID
    }
```

Wallets MUST import/export credentials in this format, but MAY store them in any format internally.
Wallets MUST validate the credential before importing it, we describe the validation procedure in this document.
Note: validating a credential does not require access to the owner's private key.

## Mina Credential Presentation

The presentation proof is encoded as follows:

```javascript
type Presentation = {
  version: "v0",
  proof: Proof,
  claims: Claims,
}
```

## Mina Credential Metadata

Metadata is a general key-value map. We standardize a few fields for interoperability across wallets:
so that e.g. wallet can display an issuer name and icon for any compatible credential.
Issuers may add their own fields as needed, such custom fields MUST NOT use the `mina` prefix.

Standardized fields are:

- `minaCredName`: The name of the credential: utf-8 encoded string.
- `minaIssuerName`: The name of the issuer: utf-8 encoded string.
- `minaDescription`: A human-readable description of the credential: utf-8 encoded string.
- `minaIcon`: A byte array representing an icon for the credential.

Any fields (inlcuding the standardized ones) MAY be omitted,
wallets MUST handle the absence of any field gracefully, e.g. with a default icon.
Wallets MUST NOT make trust decisions based on metadata, in particular,
wallets MUST NOT verify the issuer based on the `minaIssuerName` field.
Wallets MAY ignore ANY metadata field.

```javascript
type Metadata = {
  minaCredName: String,
  minaIssuerName: String,
  minaDescription: String,
  minaIcon: Uint8Array, // svg, jpg, png, webp, etc.
  ...
}
```

The `metaHash` field of the credential is the hash of the metadata.
The `metaHash` fiueld MUST be computed using `Keccak256` over the metadata.

```javascript
metaHash = Keccak256.hash(metadata)
```


# Authenticate Owner

## Authenticate Public Key Owner

[context, issuer, credHash]

```javascript
function verifyOwnerPublicKey(
  credentials: Credential[],
  authMsg: Field
) {
  // check the owners identity
  for (let credential of credentials) {
    Poseidon.hashWithPrefix(
      "mina-cred:v0:owner:pk", // sep. the domain of "public key" and "DID" owners
      ownerPk
    ).assertEquals(credential.owner);
  }

  // verify the credential owners signature on authMsg
  ownerSignature.verifyWithPrefix(
    "mina-cred:v0:owner-signature",
    ownerPk,
    authMsg
  );
}
```

## Authenticate DID Owner

```javascript
function verifyOwnerDID(
  authMsg: Field,
  credentials: Credential[],
) {
  // check the owners identity
  for (let credential of credentials) {
    Poseidon.hashWithPrefix(
      "mina-cred:v0:owner:did",
      ownerDID
    ).assertEquals(credential.owner);
  }

  // we expose ownerDID from the presentation proof
}
```

# Protocols

## Presentations

- The presentation proofs MUST NOT be reused.
- The presentation proofs MUST be generated for each presentation.
- The presentation MUST NOT contain the "context" field, which MUST be recomputed by the verifier.
- The presentation MUST NOT include the `metadata` of the credential.

### Public Inputs

The public inputs for the presentations circuits (simple and recursive) are:

```javascript
type PublicInput = {
  context: Field, // context : specified later
  claims: Claims  // application specific public inputs.
}
```

### Circuit: Presentation Validation

```javascript
class WitnessOwner {
  pk: PublicKey
  sig: Signature
  did: Field

  // convert the owner DID to an opaque "owner" hash
  ownerIdDID(): Field {
    return Poseidon.hashWithPrefix(
      "mina-cred:v0:owner:did",
      this.did
    );
  }

  // convert the owner PublicKey to an opaque "owner" hash
  ownerIdPK(): Field {
    return Poseidon.hashWithPrefix(
      "mina-cred:v0:owner:pk",
      this.pk
    );
  }

  // verify that the claimed owner authorized the presentation
  verify(authMsg: Field, ownerDID: Field) {
    // verify did owner
    ownerDID.assertEquals(this.did);

    // verify owner signature on authMsg
    this.ownerSignature.verifyWithPrefix(
      "mina-cred:v0:owner-signature",
      this.pk,
      authMsg
    );
  }
}

class WitnessCredential {
  // the type of the credential owner
  ownerType: "pk" | "did";

  // the attributes / fields of the credential
  credential: Credential;

  // data proving that the "issuer" issued the credential
  issuance: WitnessIssuance;

  // credential hash is uniform across owner types
  // (DID / PK) and credential types (recursive / simple)
  hash(): Field {
    return Poseidon.hashPacked(Credential, this.credential);
  }

  // compute the issuer identity of the credential
  issuer(): Field {
    switch (this.issuance.type) {
      case "simple":
        // simply a signed set of attributes
        return Poseidon.hashWithPrefix(
          "mina-cred:v0:simple",
          this.issuance.issuerPK
        );
      case "recursive":
        // recursively computed relation
        return Poseidon.hashWithPrefix(
          "mina-cred:v0:recursive",
          [
            this.issuance.credVK,
            this.issuance.credIdent
          ]
        );
    }
  }

  // compute the owner identity of the credential
  // (corresponding to either a public key or a DID)
  verify(
    owner: WitnessOwner,
  ) {
    // verify the owner field
    switch (this.ownerType) {
      case "pk":
        owner.ownerIdPK().assertEquals(credential.owner);
      case "did":
        owner.ownerIdDID().assertEquals(credential.owner);
    }

    // verify the issuance of the credential
    switch (this.witness.type) {
      case "simple":
        // verify the credential signature
        issuerSignature.verify(
          "mina-cred:v0:issuer-signature",
          this.issuance.issuerPK,
          this.hash(),
        );

      case "recursive":
        // verify the credential proof
        this.issuance.credProof.publicInput.assertEquals([
          self.hash(),            // the hash of the attributes
          this.issuance.credIdent // additional public input (e.g. a hash of an RSA key)
        ]);
        this.issuance.credProof.verify();
    }
  }
}
```

```javascript
type PrivateInput = {
  rand: Field,
  owner: WitnessOwner,
  credentials: WitnessCredential[],
}

type PublicInput = {
  context: Field,  // context binding the presentation
  authMsg: Field,  // signed by the owner: MAY be omitted when owner is always a public key
  ownerDID: Field, // DID of the owner: MAY be omitted when owner is always a public key
  claims: Claims,  // application specific public inputs
}

// compute the authentication message:
// signed by the owner
let authMsg = Poseidon.hashWithPrefix(
  "mina-cred:v0:auth-msg", // sep. for Poseidon used as a blinding commitment
  rand,                    // randomness for the commitment
  context,                 // context of the presentation
  // first credential
  witCred[0].hash(),
  witCred[0].issuer(),
  // second credential
  witCred[1].hash(),
  witCred[1].issuer(),
  // third credential
  ...
  // last credential
  witCred[N].hash(),
  witCred[N].issuer(),
]);

// message commitment exported for DID integration
authMsg.assertEquals(publicInput.authMsg);

// verify each credential issuance
for (let credential of credentials) {
  credential.verify(owner);
}

// verify owner identity
owner.verify(
  publicInput.authMsg,
  publicInput.ownerDID
);

// verify application constraints
applicationConstraints(
  [
    (
      credentials[0].issuer(), credentials[0].credential,
      credentials[1].issuer(), credentials[1].credential,
      ...
      credentials[N].issuer(), credentials[N].credential
    ),
  ],
  claims
)
```

WARNING: The following serves to help mitigate "owner confusion attacks",
where an owner (e.g. DID) is used in-circuit belonging to
another party but which has not been authenticated.

If the number of DID owned credentials is 0, the `owner.did` field MAY be omitted from the implementation,
if it is present it MUST be the zero field element.
If the number of Public Key owned credentials is 0,  the `owner.pk` field MAY be omitted from the implementation,
if it is present it MUST be the dummy public key corresponding to a secret key of 1.
The implementation SHOULD NOT provide a way to extract the `owner.did` or `owner.pk` from a credential,
but MAY allow testing for equality with other witnessed values.

Implementation MUST NOT provide direct access to the fields of the `owner` object,
namely `owner.did` and `owner.pk` without logic to ensure that the


#### Hiding the DID

The specification outlines how to create a presentation for a public DID,
e.g. prove that a particular ID is associated with a person above a certain age.
We forsee applications where the DID is not public.
Such cases will require application-specific cryptographic engineering:

In the case there the number of DID owned credentials is non-zero,
the public inputs `publicInput.ownerDID` and `publicInput.authMsg`
MAY be omitted, in such scenarios the application logic MUST validate the DID:
e.g. looking up the DID in a Merkle tree and retrieving a public key from the DID document in the corresponding leaf.

#### Specialized Implementations

Implementations MAY be universal, allowing the verification of both types of credentials with both types of owners.
Implementations MAY also be specialized, only allowing the verification of a specific type of credential with a specific type of owner,
in such cases unnecessary code MAY be omitted to reduce the size of the circuit:

- If the number of DID owned credentials is 0:

- If only public key owners are supported: the DID verification code MUST be omitted.
  - The `rand` field MAY be fixed to zero.
  - The public output `publicInput.ownerDID` MAY be omitted or MUST be fixed to zero.
  - The public output `publicInput.authMsg` MAY be omitted.

- If only recursive credentials are supported:
  the simple credential verification code (checking the issuer signature) MUST be omitted.

- If only simple credentials are supported:
  the recursive credential verification code (checking the recursive SNARK) MUST be omitted.

# Context Binding

The verifier computes the context (out-of-circuit) as:

```javascript
context = Poseidon.hashWithPrefix(
  "mina-cred:v0:context:<TYPE>", // for versioning and type separation
  [
    presentationVK.hash, // binds the presentation to the relation
    verifierIdentity,    // verifiers identifier
    nonce,               // a random nonce to prevent replay attacks
    action,              // the "action" being performed (e.g. login, transaction hash etc.)
    claims,              // the public input (the set of "claims" being presented)
  ]
)
```

Where `TYPE` is a constant "type" of the presentation, seperating e.g. zkApp interactions from HTTP requests.

The `nonce` MUST be generated as follows:

```javascript
let nonce = Poseidon.hashWithPrefix(
  "mina-cred:v0:nonce",
  [serverNonce, clientNonce]
)
```

- The `clientNonce` MUST be a uniformly random field element generated by the client.
- The `clientNonce` MUST never be reused.
- The `serverNonce` MAY be zero in applications where storing the set of expended nonces indefinitely is not a concern.

Usual applications of `serverNonce` is to seperate the nonce space into "epochs" to prevent storage of all nonces indefinitely:
for instance, a timestamp may be used and validity requires the timestamp to be recent.
Allowing the server to only store nonces for a limited time.

## zkApp

The `TYPE` MUST be `zk-app`.

```javascript
let verifierIdentity = "Mina Address of the ZK App"

let action = Poseidon.hash([METHOD_ID, ARG1, ARG2, ...])
```

The ZK app MUST check the validity of the presentation proof and the claims.

## Web Application

The `TYPE` MUST be `https`.

[Uniform Resource Identifier](https://datatracker.ietf.org/doc/html/rfc3986)

```javascript
let verifierIdentity = Keccak256.hash("example.com");

let action = Keccak256.hash(HTTP_REQUEST);
```

The scheme MUST be `https`.

Keccak is used to improve efficiency when the HTTP request is long: such as uploading a file.

QUESTION: solving the chicken-and-egg problem, where to include the proof?

## JSON-RPC and REST

Specify how to "sign" a JSON document using the presentation proof.

```javascript
let verifierIdentity = Keccak256.hash("example.com");

let action = Keccak256.hash(serialize-json-canonically);

// add the proof to the JSON-RPC request

```
