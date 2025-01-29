# Mina Attestations

This is a TypeScript library that implements _private attestations_: A cryptographic protocol that allows you to selectively disclose facts about yourself.

**Try our demo: [mina-attestations-demo.zksecurity.xyz](https://mina-attestations-demo.zksecurity.xyz)**

The attestation flow usually involves three parties:
1. an _issuer_ that makes a statement about you and hands you a certificate of that statement: a _credential_.
  * Example: Your passport is a credential issued by a government agency. It contains valuable information about you.
2. a _verifier_ that is interested in some particular fact about you (that is contained in a credential).
  * Example: To sign up users, a crypto exchange must check that they are not US citizens. The exchange acts as a verifier.
3. you, the _user_, who controls your own credentials. You can decide to create privacy-preserving _presentations_ of a credential, disclosing just the information that a verifier needs to know.
  * Example: Prompted by the crypto exchange's request, you create a presentation about your passport, proving that it comes from a non-US country.

<!-- TODO: add diagram -->

Mina Attestations helps you implement all parts of the flow described above. The main lift is an easy-to-use API to create presentation requests and fulfill them with existing credentials:

```
npm i mina-attestations
```

```ts
// TODO simple example showing presentation request + create
```

## Resources and background

TODO: references to various md docs and papers and examples

## Usage

TODO

## Bonus: `mina-attestations/dynamic`

Under the sub-import `mina-attestations/dynamic`, we export an entire library of dynamic data types and hashes with o1js.

Features:

- `DynamicSHA2` for hashing dynamic-length inputs with SHA2-256, -224, -384 or -512
- `DynamicString` and `DynamicBytes` for representing strings and bytes
- `DynamicArray`, a generalization of the above types to an arbitrary element type
- `StaticArray`, which provides an API consistent with `DynamicArray` but for _fixed-length_ arrays (which aren't well-supported in o1js either)
- `DynamicRecord`, a wrapper for objects that you don't necessarily know the exact layout of, but can be hashed and accessed properties of inside a circuit
- `hashDynamic()`, for Poseidon-hashing pretty much any input (including plain strings, records, o1js types etc) in a way which is compatible to in-circuit hashing of padded data types like `DynamicRecord` and `DynamicArray`

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

## Acknowledgement

We thank Mina Foundation for funding this work with a grant.

Original grant proposal: https://github.com/MinaFoundation/Core-Grants/issues/35#issuecomment-2318685738

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
