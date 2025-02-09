# Mina Attestations &nbsp; [![npm version](https://img.shields.io/npm/v/mina-attestations.svg?style=flat)](https://www.npmjs.com/package/mina-attestations)

This is a TypeScript library that implements _private attestations_: A cryptographic protocol that allows you to selectively disclose facts about yourself, using zero-knowledge proofs.

**Try our demo: [mina-attestations-demo.zksecurity.xyz](https://mina-attestations-demo.zksecurity.xyz)**

The library is available on npm and designed for all modern JS runtimes.

```
npm i mina-attestations
```

## What are private attestations?

The attestation flow usually involves three parties:

1. an _issuer_ that makes a statement about you and hands you a certificate of that statement: a _credential_.

- Example: Your passport is a credential issued by a government agency. It contains valuable information about you.

2. a _verifier_ that is interested in some particular fact about you (that is contained in a credential).

- Example: To sign up users, a crypto exchange must check that they are not US citizens. The exchange acts as a verifier.

3. you, the _user_, who controls your own credentials. You can decide to create privacy-preserving _presentations_ of a credential, disclosing just the information that a verifier needs to know.

- Example: Prompted by the crypto exchange's request, you create a presentation about your passport, proving that it comes from a non-US country.
- The crypto exchange never learns any other information contained in your passport, and can still trust your presentation.

<!-- TODO: add diagram -->

## Features

Mina Attestations helps you implement all parts of the flow described above.

- bullet
- point
- list

<!-- One of the main contributions is a DSL to specify the attestations a verifier wants to make about a user. -->

<!--
Under the hood, private attestations rely on [zero-knowledge proofs](https://en.wikipedia.org/wiki/Zero-knowledge_proof).
Mina Attestations builds on top of [o1js](https://github.com/o1-labs/o1js), a general-purpose zk framework for TypeScript. -->

## Example: Defining a private attestation

Continuing from the example before, the crypto exchange might specify their conditions on the user's passport as follows:

```ts
import { PresentationSpec, Claim, Operation } from 'mina-attestations';
import { UInt64 } from 'o1js';
import { PassportCredential } from './credential-specs.ts';

let spec = PresentationSpec(
  { passport: PassportCredential.spec, createdAt: Claim(UInt64) },
  ({ passport, createdAt }) => ({
    assert: [
      // not from the United States
      Operation.not(
        Operation.equals(
          Operation.property(passport, 'nationality'),
          Operation.constant(
            PassportCredential.Nationality.from('United States')
          )
        )
      ),
      // passport is not expired
      Operation.lessThanEq(
        createdAt,
        Operation.property(passport, 'expiresAt')
      ),
    ],
  })
);
```

> Note: This example is simplified, see [our code example](https://github.com/zksecurity/mina-attestations/blob/main/examples/mock-zk-passport.eg.ts) for more details.

The Attestation DSL is, essentially, a radically simplified language for specifying zk circuits, tailored to the use case of making statements about user data. It has several advantages over a general-purpose circuit framework like o1js:

- Simple enough to be readable by a user (in pretty-printed form), who wants to understand what private information is shared
- Fully serializable into space-efficient JSON. No concerns about malicious code execution when used to produce zk proofs from a trusted environment, like a wallet
- Easier to write and harder to mess up for developers

## What credentials does Mina Attestations support?

Explain native vs imported

## API

TOC with links

### Data types

### Creating credentials

### Defining and requesting a presentation

### Creating presentations

### Verifying presentations

## Bonus: `mina-attestations/dynamic`

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

We thank the [zk-email project](https://github.com/zkemail) for creating and open-sourcing zk-email. We took great inspiration for our own (unfinished) zk-email implementation. Our TS code that prepares emails for in-circuit verification was seeded by copying over a large amount of from [zk-email-verify](https://github.com/zkemail/zk-email-verify); some parts of it still exist in our code almost unchanged.

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
