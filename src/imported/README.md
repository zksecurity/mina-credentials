# Imported Credentials

This folder contains specs for **imported credentials**.

Imported credentials are those that cannot be verified with cheap native operations, and are therefore wrapped in a recursive proof.

Specs for several imported credentials are available under the import `mina-attestations/imported`.

```ts
import { EthereumEcdsa } from 'mina-attestations/imported';

const EcdsaCred = await EcdsaEthereum.Credential({ maxMessageLength });

// use `EcdsaCred` to:
// - import ecdsa signatures
// - require ecdsa signatures as inputs to attestation specs
```
