import { PrivateKey, Signature } from 'o1js';
import { NestedProvable } from '../src/nested.ts';

export { createSignatureCredential };

function createSignatureCredential<Data>(type: NestedProvable, data: Data) {
  let issuer = PrivateKey.randomKeypair();
  let signature = Signature.create(
    issuer.privateKey,
    NestedProvable.get(type).toFields(data)
  );
  return {
    private: { issuerPublicKey: issuer.publicKey, issuerSignature: signature },
    data,
  };
}
