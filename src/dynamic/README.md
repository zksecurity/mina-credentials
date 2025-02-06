# Dynamic o1js

This folder contains types, provable methods and zkprograms to handle _dynamic data structures_ in o1js, such as strings, or records with a variable number of keys.

"Dynamic o1js" can be seen as its own, self-contained library which is generally useful, beyond attestations. It can be imported from `mina-attestations/dynamic`.

In `mina-attestations`, dynamic o1js types are used in two main ways:

- To support dynamic schemas for signed credentials
- To implement circuits that import real-life credentials

## Dynamic schemas

For example, assume that someone hashes the object `{ name: "Peter L. Montgomery", birthdate: -702784800000 }`, signs the hash and issues the result as a credential.

In Mina Attestations, it is possible to use that credential for an attestation that

- only cares about the `birthdate` property
- is not aware that the credential has a `name` property
- in _particular_, does not know the length of the name up front

This is possible because the in-circuit hashing algorithm doesn't hard-code any of these aspects. It can hash _any_ record, and also prove that it contains a `birthdate` property with a given value.

## Real-life credentials

As an example, take emails: To verify DKIM signature and import emails as credentials, we need to hash a variable-length body and header using SHA-256.

Why can't we hard-code the body and header length in our circuit?

Well, that would mean the verifier of an attestation also needs to know about the precise length of your email, and has to compile a custom zkprogram for that exact length. But that makes no sense, first because we want to hide the email content including its length, and second because the verifier wants to verify using a single verification key computed up front.
