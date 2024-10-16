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

# Formats

## Mina Credential

```javascript
type credential = {
  owner: PublicKey,       // the owners public key
  metaHash: Field,        // hash of arbitrary metadata
  attributes: Attributes, // struct of hidden attributes (e.g. age, name, SSN)
}
```

```javascript
type Witness =
  | { type: "simple",
      issuer: PublicKey,
      issuerSignature: Signature,
    }
  | { type: "recursive",
      vk: VerificationKey,
      credIdent: Field,
      credProof: Proof,
    }
```

```javascript
type storedCredential = {
  witness: Witness,
  metadata: Metadata,
  credential: Credential,
}
```

## Mina Credential Presentation

```javascript
type presentation = {
  proof: Proof,
  claims: Claims,
}
```

The presentation MUST NOT contain the "context" field, which MUST be recomputed by the verifier.

## Mina Credential Metadata

Metadata is a general key-value map. We standardize a few fields for interoperability across wallets:
so that e.g. wallet can display an issuer name and icon for any compatible credential.
Issuers may add their own fields as needed.
Standardized fields are:

- `credName`: The name of the credential.
- `issuerName`: The name of the issuer.
- `description`: A human-readable description of the credential.
- `icon`: A byte array representing an icon for the credential.

Any standardized fields MAY be omitted, wallets MUST handle the absence of any field gracefully, e.g. with a default icon.
Wallets MUST NOT make trust decisions based on metadata, in particular,
wallets MUST NOT verify the issuer based on the `issuerName` field.
Wallets MAY ignore ANY metadata field.

```javascript
type metadata = {
  credName: String,
  issuerName: String,
  description: String,
  icon: Bytes, // jpg, png, webp, etc.
  ...
}
```

The `metaHash` field of the credential is the hash of the metadata.
The `metaHash` fiueld MUST be computed using `Keccak256` over the metadata.

```javascript
metaHash = Keccak256.hash(metadata)
```

# Protocols

## Presentations

Presentation proofs MUST not be reused.
Presentation proofs MUST be generated for each presentation.

### Public Inputs

```javascript
type PublicInput = {
  context: Field, // context : specified later
  claims: Claims  // application specific public inputs.
}
```

### Circuit: Present Simple Credential

A standardized circuit for presenting simple credentials.

The circuit verifies two signatures: one from the issuer and one from the owner.

```javascript
// the private inputs for the circuit
type PrivateInput = {
  credential: Credential,
  issuerPk: PublicKey,
  issuerSignature: Signature,
  ownerSignature: Signature,
}

// hash the credential
let credHash = Poseidon.hashPacked(Credential, credential);

// verify the credential issuer signature
issuerSignature.verify(issuerPk, credHash);

// convert issuerPK to opaque field element
let issuer = Poseidon.hashWithPrefix(
  "mina-cred:v0:simple",  // sep. the domain of "simple" and "recursive" issuers
  issuerPk
);

// verify the credential owners signature
ownerSignature.verify(owner, [credHash, issuer, context]);

// verify application specific constraints using the standard API
applicationConstraints(
  credential, // hidden attributes/owner
  issuer,     // potentially hidden issuer
  claims,     // application specific public input
)
```

### Circuit: Present Recursive Credential

A standardized circuit for presenting recursive credentials.

The circuit verifies a proof "from" the issuing authority and a signature from the owner.

```javascript
// the private inputs for the circuit
type PrivateInput = {
  vk: VerificationKey,
  credIdent: Field,
  credProof: Proof,
  credential: Credential,
  ownerSignature: Signature,
}

// hash the credential
let credHash = Poseidon.hashPacked(Credential, credential);

// verify the credential proof
credProof.publicInput.assertEquals([credHash, credIdent]);
credProof.verify(vk).assertEqual(true);

// the issuer is identified by the recursive relation and public input
let issuer = Poseidon.hashWithPrefix(
  "mina-cred:v0:recursive", // sep. the domain of "simple" and "recursive" issuers
  [vk.hash, credIdent]      // identifies the issuing authority / validation logic
);

// verify the credential owners signature
ownerSignature.verify(owner, [credHash, issuer, context]);

// verify application specific constraints using the standard API
applicationConstraints(
  credential, // hidden attributes/owner
  issuer,     // potentially hidden issuer
  claims,     // application specific public input
)
```

# Context Binding

The verifier computes the context (out-of-circuit) as:

```javascript
context = Poseidon.hashWithPrefix(
  "mina-cred:v0:context", // for versioning
  [
    // the verification key hash (of the presentation circuit)
    presentationCircuitVK.hash,
    claims,           // the public input (the set of "claims" being presented)
    nonce,            // a random nonce
    verifierIdentity, // a URI for the verifiers identifier (see below)
    action,           // the "action" being performed (e.g. login, transaction hash etc.)
  ]
)
```

The nonce MUST be a uniformly random value generated by the prover.

## ZK App

verifier = Mina address

action = Method with arguments (note one of the args is the presentation proof).


## Web Application

[Uniform Resource Identifier](https://datatracker.ietf.org/doc/html/rfc3986)

```javascript
let verifier = Keccak256.hash("https://example.com/verify");

let action = Keccak256.hash(HTTP_REQUEST);
```

The scheme MUST be `https`.
