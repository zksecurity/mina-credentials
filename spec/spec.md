# Technical Specification for Mina Credentials

This document is a low-level technical specification for the Mina Credentials system.
It is intended as documentation for the accompanying codebase and implementers.
It does not include security proofs or motivations for the design choices;
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
  owner: Field,       // credential owner's identifier (references a DID or public key)
  meta: Field,        // hash of arbitrary metadata
  app: AppAttributes, // application-specific attributes (e.g. name, age, etc.)
}
```

It is stored along with metadata and the version of the credential:

```javascript
type Issuance =
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
  issuance: Issuance,
  metadata: Metadata,
  credential: Credential,
}
```

```javascript
type OwnerIdentity = {
  | { type: "pk",
      pk: PublicKey,  // native Mina public key
    }
  | { type: "did",
      did: Field,     // hash of a DID
    }
}

type OwnerProof =
  | { type: "pk",
      pk: PublicKey,  // public key of the owner
      sig: Signature, // signature under the owner's public key
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

Mina credentials include general metadata, which is not accessible from within the circuits.
Metadata is a general key-value map. We standardize a few fields for interoperability across wallets
so that e.g. wallets can display an issuer name and icon for any compatible credential.
Issuers may add their own fields as needed; such custom fields MUST NOT use the `mina` prefix.

Standardized fields are:

- `minaCredName`: The name of the credential: utf-8 encoded string.
- `minaIssuerName`: The name of the issuer: utf-8 encoded string.
- `minaDescription`: A human-readable description of the credential: utf-8 encoded string.
- `minaIcon`: A byte array representing an icon for the credential.

```javascript
type Metadata = {
  minaCredName: String,
  minaIssuerName: String,
  minaDescription: String,
  minaIcon: Uint8Array, // svg, jpg, png, webp, etc.
  ...
}
```

The `metaHash` field of the credential is the hash of the metadata structure:

```javascript
metaHash = Keccak256.hash(metadata)
```

Implementations MUST adhere to the following:

- Any fields (including the standardized ones) MAY be omitted
- Wallets MUST handle the absence of any field gracefully, e.g. with a default icon
- Wallets MUST NOT make trust decisions based on metadata, in particular
- Wallets MUST NOT verify the issuer based on the `minaIssuerName` field
- Wallets MAY ignore ANY metadata field
- Wallets MUST verify the `metaHash` field of the credential against the `Metadata` structure when importing it
- The `metaHash` field MUST be computed using `Keccak256` over the metadata

# Authenticate Owner

## Authenticate Public Key Owner

```javascript
function verifyOwnerPublicKey(
  credentials: Credential[],
  authMsg: Field
) {
  // check the owner's identity
  for (let credential of credentials) {
    Poseidon.hashWithPrefix(
      "mina-cred:v0:owner:pk", // separate the domain of "public key" and "DID" owners
      ownerPk
    ).assertEquals(credential.owner);
  }

  // verify the credential owner's signature on authMsg
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
  // check the owner's identity
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

The public inputs for the presentation circuits (simple and recursive) are:

```javascript
type PublicInput = {
  ownerDID: Optional[Field], // the owner's DID
  authMsg: Optional[Field],  // the message to be signed by the owner
  context: Field,            // context: specified later
  claims: Claims             // application specific public inputs.
}
```

### Circuit: Presentation Validation

```javascript
class WitnessOwner {
  pk: PublicKey
  sig: Signature
  did: Field
  rnd: Field // blinding factor for blindMsg

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
  verify(
    authMsg: Field,  // message authorizing the presentation
    didOwner: Field  // the owner's DID (for DID use)
    didBlindMsg: Field, // hiding commitment to authMsg (for DID use)
  ) {
    // verify authMsg commitment and owner DID
    // (for DID signature validation outside the circuit only)
    didOwner.assertEquals(this.did);
    Poseidon.Hash(
      this.rnd,
      authMsg
    ).assertEquals(didBlindMsg);

    // verify owner signature on authMsg
    // (for public key owner signature inside the circuit only)
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
    var fields = []
    for (key, value) in this.credential {
      fields.append(Poseidon.hashWithPrefix(key, value));
    }

    //
    return Poseidon.hash(fields);
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
  owner: WitnessOwner,              // witness proving ownership
  credentials: WitnessCredential[], // credentials used to prove claims
}

type PublicInput = {
  context: Field,     // context binding the presentation
  didOwner: Field,    // DID of the owner: MAY be omitted when owner is always a public key
  didBlindMsg: Field, // hiding commitment to authMsg: MAY be omitted when owner is always a public key
}

// compute the authentication message:
// signed by the owner (public key or DID)
let authMsg = Poseidon.hash(
  context, // context of the presentation
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

// verify each credential issuance
for (let credential of credentials) {
  credential.verify(owner);
}

// verify owner identity
owner.verify(
  authMsg,
  publicInput.didOwner,   // for DID only
  publicInput.didBlindMsg // for DID only
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

Implementation MUST NOT provide direct access to the fields of such an `owner` object, namely `owner.did` and `owner.pk`.
Instead, they SHOULD implement an interface to retrieve the owners identity for *each individual credential*, e.g. `credentialsI.owner()`.
Implementations MAY also implement an interface to retrieve the DID or public key of the owner, e.g. `credential.did()` or `credential.pk()`,
in such cases, the implementation MUST ensure that the `owner` of the credential matches the correct type.

#### Hiding the DID

The specification outlines how to create a presentation for a *public DID*,
i.e. the attributes/credentials are hidden, but the owners identity is revealed.
This is done to move the logic of authenticating the ownership of the DID outside of the circuit:
e.g. looking up the corresponding DID document on a public ledger and verifying the signature on the `authMsg`.
We foresee applications where the DID should not be public, applications include looking up the DID in a Merkle tree to retrieve a public key.
Such applications depend on the concrete format of the accompanying DID document and is beyond the scope of this specification.

In cases where the number of DID-owned credentials is non-zero,
the public inputs `publicInput.didOwner` and `publicInput.didBlindMsg`
MAY be omitted. In such scenarios the application logic MUST validate
the DID by other means beyond the scope of this specification.

#### Specialized Implementations

Implementations MAY be universal, allowing the verification of both types of credentials with both types of owners.
Implementations MAY also be specialized, only allowing the verification of a specific type of credential with a specific type of owner.
In such cases unnecessary code MAY be omitted to reduce the size of the circuit:

- If the number of DID-owned credentials is 0:

- If only public key owners are supported: the DID verification code MUST be omitted.
  - The `rand` field MAY be fixed to zero.
  - The public output `publicInput.ownerDID` MAY be omitted or MUST be fixed to zero.
  - The public output `publicInput.authMsg` MAY be omitted.

- If only recursive credentials are supported:
  the simple credential verification code (checking the issuer signature) MUST be omitted.

- If only simple credentials are supported:
  the recursive credential verification code (checking the recursive SNARK) MUST be omitted.


# Verifying a Presentation

TODO: DID verification



# Context Binding

The verifier computes the context (out-of-circuit) as:

```javascript
context = Poseidon.hashWithPrefix(
  "mina-cred:v0:context:<TYPE>", // for versioning and type separation
  [
    presentationVK.hash, // binds the presentation to the relation
    verifierIdentity,    // verifier's identifier
    nonce,               // a random nonce to prevent replay attacks
    action,              // the "action" being performed (e.g. login, transaction hash etc.)
    claims,              // the public input (the set of "claims" being presented)
  ]
)
```

Where `TYPE` is a constant "type" of the presentation, separating e.g. zkApp interactions from HTTP requests.

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

Typical applications of `serverNonce` are to separate the nonce space into "epochs" to prevent storage of all nonces indefinitely:
for instance, a timestamp may be used and validity requires the timestamp to be recent,
allowing the server to only store nonces for a limited time.

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
