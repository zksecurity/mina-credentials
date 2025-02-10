# Mina Attestations &nbsp; [![npm version](https://img.shields.io/npm/v/mina-attestations.svg?style=flat)](https://www.npmjs.com/package/mina-attestations)

This is a TypeScript library that implements _private attestations_: A cryptographic protocol that allows you to selectively disclose facts about yourself, using zero-knowledge proofs.

**🎮 Try our demo: [mina-attestations-demo.zksecurity.xyz](https://mina-attestations-demo.zksecurity.xyz)**

The library is available on npm and designed for all modern JS runtimes.

```
npm i mina-attestations
```

## What are private attestations? 🧑‍🎓

The attestation flow involves three parties: _issuer_, _user_ and _verifier_. They exchange two kinds of digital objects: _credentials_ and _presentations_.

1. an **issuer** makes a statement about you and hands you a certificate of that statement: a **credential**.

> Example: Your passport is a credential issued by a government agency. It contains information such as your name, birth date and citizenship.

<!-- - A credential derives its value from the credibility of the issuer: Third parties will trust the information on your passport, because they trust your government.
- To be usable, a credential has to carry a _digital signature_ by the issuer. (For modern passports in most countries, this is the case!) -->

2. the **verifier** is interested in some particular fact about you (that is contained in a credential).

> Example: To sign up users, a crypto exchange must check that they are not US citizens. The exchange acts as a verifier.

3. the **user** owns credentials. They can create **presentations** of a credential, that only disclose the information a verifier needs to know.

> Example: Prompted by the crypto exchange's request, you create a presentation, proving that your passport comes from a non-US country.
> The crypto exchange verifies that this is true, without learning anything else about you.

<!-- TODO: add diagram? -->

To summarize, roughly, in cryptographic terms: credentials are signed data, and presentations are zero-knowledge proofs about credentials.

<!-- TODO: is this good enough as a definition of private attestations? -->

_Private attestations_ refers to the entire protocol sketched above. A synonymous term from the academic literature is [anonymous credentials](https://www.sciencedirect.com/topics/computer-science/anonymous-credential).

<!-- TODO see [below](LINK) ? -->

## Features 💫

Mina Attestations helps you implement all parts of the private attestation flow.

- ✅ Supports [issuing credentials](#creating-credentials) as well as [requesting](#requesting-presentations),
  [creating](#creating-presentations) and [verifying](#verifying-presentations) presentations
- 🪪 [Import real-world credentials](#credential-kinds), like passports or emails, by wrapping them in a zk proof
- 💡 Selective disclosure logic is defined with the embedded [`Operation` DSL](#attestation-dsl) that is feature-rich, yet simple enough for non-technical users to understand what data they share
- 🔒 Designed for integration in crypto wallets, to store credentials and authorize presentations by a signature
  - Integration in the [Pallad](https://pallad.co) wallet is underway
- 🧠 The cryptographic protocol is carefully designed to provide strong safety guarantees:
  - **Ownership**: Credentials are tied to their owner, a Mina public key, and become invalid when changing the owner.
  - **Unforgeability**: Presentations can only be created with access to their underlying credentials and an owner signature. So, credentials can even be stored with third parties without risking impersonation (if giving up privacy to those parties is acceptable).
  - **Privacy**: Presentations do not leak any data from the input credential or the owner, apart from the specific public statement they were designed to encode <!-- (which can be reviewed by the user before giving authorization) -->.
  - **Unlinkability**: Two different presentations of the same credential, or by the same user, cannot be linked (apart from out-of-band correlations like the user's IP address)
  - **Context-binding**: Presentations are bound to a specific context such as the origin of the requesting website, so that the verifier cannot man-in-the-middle and impersonate users at a third party.

Zero-knowledge proofs are implemented using [o1js](https://github.com/o1-labs/o1js), a general-purpose zk framework.

<!-- One of the main contributions is a DSL to specify the attestations a verifier wants to make about a user. -->

<!--
Under the hood, private attestations rely on [zero-knowledge proofs](https://en.wikipedia.org/wiki/Zero-knowledge_proof).
Mina Attestations builds on top of [o1js](https://github.com/o1-labs/o1js), a general-purpose zk framework for TypeScript. -->

## Example: Defining a private attestation <a id="attestation-dsl"></a>

<!-- TODO: rewrite to use a native credential and not rely on non-existing imports -->

Using an example similar to the one before, a verifier might specify their conditions on the user's credential with the following code:

```ts
import {
  Claim,
  Credential,
  DynamicString,
  Operation,
  PresentationSpec,
} from 'mina-attestations';
import { UInt64 } from 'o1js';

const String = DynamicString({ maxLength: 100 });

// define expected credential schema
let credential = Credential.Native({
  name: String,
  nationality: String,
  expiresAt: UInt64,
});

let spec = PresentationSpec(
  // inputs: credential and an additional "claim" (public input)
  { credential, createdAt: Claim(UInt64) },
  // logic
  ({ credential, createdAt }) => ({
    // we make two assertions:
    assert: [
      // 1. not from the United States
      Operation.not(
        Operation.equals(
          Operation.property(credential, 'nationality'),
          Operation.constant(String.from('United States'))
        )
      ),

      // 2. credential is not expired
      Operation.lessThanEq(
        createdAt,
        Operation.property(credential, 'expiresAt')
      ),
    ],
    // we expose the credential's issuer, for the verifier to check
    outputClaim: Operation.issuer(credential),
  })
);
```

There's much to unpack in this example, but the main thing we want to highlight is how the custom logic for the presentation is defined, in the call to `PresentationSpec()`.

First we define the type of credential we expect, using `Credential.Native()`. That `credential` type is declared to be one of the inputs to the presentation, along with a second input called `createdAt`.

<!--
First, we declare the type of credential we expect by calling `Credential.Native()` with a set of data attributes. These attributes are set to "provable types", that would often be imported from o1js, like `UInt64` in the example. The example also instantiates its own provable type, `String`, using the `DynamicString` constructor from our library. This -->

Note again that in a typical flow, this code would live somewhere in the application of a verifier. It would be used as the basis to create a [presentation request](#defining-and-requesting-a-presentation) TODO

> 🤓 By interacting with this code in your editor, you might appreciate that all our library interfaces are precisely typed, using generic types to preserve as much information as possible. For example, the inferred type of `credential`, which is passed as an input to `PresentationSpec`, is carried into the callback. There, `Operations.property(credential, 'nationality')` is correctly inferred to be a `String`. This, in turn, ensures that a `String` is also passed to the `Operation.constant()`, because `Operations.equal()` requires its inputs to be of equal type.

> Note: This example is simplified, see [our code example](https://github.com/zksecurity/mina-attestations/blob/main/examples/mock-zk-passport.eg.ts) for more details.

The Attestation DSL is, essentially, a radically simplified language for specifying zk circuits, tailored to the use case of making statements about user data. It has several advantages over a general-purpose circuit framework like o1js:

- Simple enough to be readable by a user (in pretty-printed form), who wants to understand what private information is shared
- Fully serializable into space-efficient JSON. No concerns about malicious code execution when used to produce zk proofs from a trusted environment, like a wallet
- Easier to write and harder to mess up for developers

## What credentials are supported? <a id="credential-kinds"></a>

TODO Explain native vs imported, stress what "importing" means & what could be done & what is already done

## API

TOC with links

### Data types

### Creating credentials

### Defining presentation logic

### Requesting presentations

### Creating presentations

### Verifying presentations

## Bonus: `mina-attestations/dynamic`

<!-- Rename the lib to `o1js-dynamic` and publish as its own npm package, to make it look less mina-attestations specific and more likely to be adopted everywhere -->

Under the sub-import `mina-attestations/dynamic`, we export an entire library of dynamic data types and hashes with o1js.

Features:

- `DynamicSHA2` for hashing dynamic-length inputs with SHA2-256, -224, -384 or -512
- `DynamicSHA3` for hashing dynamic-length inputs with Keccak256
- `DynamicString` and `DynamicBytes` for representing strings and bytes, with many useful methods for manipulating strings in a circuit
- `DynamicArray`, a generalization of the above types to an arbitrary element type
- `StaticArray`, which provides an API consistent with `DynamicArray` but for fixed-length arrays
- `DynamicRecord`, a wrapper for objects that you don't necessarily know the exact layout of, but can be hashed and accessed properties of inside a circuit
- `hashDynamic()`, for Poseidon-hashing pretty much any input (including plain strings, records, o1js types etc) in a way which is compatible to in-circuit hashing of padded data types like `DynamicRecord` and `DynamicArray`
- `toDecimalString()`, a gadget to compute the variable-length decimal string from a `Field`

The sub-library is intended to help with importing **real-world credentials** into the Mina ecosystem: For example, to "import" your passport, you have to verify the passport authority's signature on your passport data. The signature relies one of several hashing and signature schemes such as ECDSA, RSA and SHA2-256, SHA2-384, SHA2-512. Also, the signature will be over a dynamic-length string.

Example of SHA-512-hashing a dynamic-length string:

```ts
import { Bytes, ZkProgram } from 'o1js';
import { DynamicSHA2, DynamicString } from 'mina-attestations/dynamic';

// allow strings up to length 100 as input
const String = DynamicString({ maxLength: 100 });

let sha512Program = ZkProgram({
  name: 'sha512',
  publicOutput: Bytes(64); // 64 bytes == 512 bits

  methods: {
    run: {
      privateInputs: [String],
      async method(string: DynamicString) {
        let publicOutput = DynamicSHA2.hash(512, string);
        return { publicOutput };
      },
    },
  },
});

await sha512Program.compile();

let result = await sha512Program.run(String.from('Hello, world!'));
let provenHash: Bytes = result.proof.publicOutput;

console.log(provenHash.toHex());
```

## Further resources and background

TODO: references to various md docs and papers and examples

## Acknowledgement

We thank [Mina Foundation](https://www.minafoundation.com/) for funding this work with a grant, and for providing us with valuable feedback and direction throughout. Link to the original grant proposal: https://github.com/MinaFoundation/Core-Grants/issues/35#issuecomment-2318685738

We thank o1Labs for maintaining and open-sourcing [o1js](https://github.com/o1-labs/o1js). Some of our code, such as the SHA2, Keccak and RSA gadgets, were seeded by copying code from the o1js repo and modifying it to fit our needs.

We thank the [zk-email project](https://github.com/zkemail) for creating and open-sourcing zk-email. We took great inspiration for our own (unfinished) zk-email implementation. Our TS code that prepares emails for in-circuit verification was seeded by copying over a large amount of code from [zk-email-verify](https://github.com/zkemail/zk-email-verify); some parts of it still exist in our code almost unchanged.

## License

[Apache-2.0](LICENSE)

Copyright 2024-2025 zkSecurity

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
