import { PrivateKey, Signature } from 'o1js';
import { NestedProvable } from '../src/nested.ts';

export { createAttestation };

function createAttestation<Data>(type: NestedProvable, data: Data) {
  let issuer = PrivateKey.randomKeypair();
  let signature = Signature.create(
    issuer.privateKey,
    NestedProvable.get(type).toFields(data)
  );
  return { public: issuer.publicKey, private: signature, data };
}
