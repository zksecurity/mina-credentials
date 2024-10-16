import { PrivateKey, Signature } from 'o1js';
import { NestedProvable } from '../src/nested.ts';
import { Credential } from '../src/credentials.ts';

export { createSignatureCredential, owner, ownerKey };

const { publicKey: owner, privateKey: ownerKey } = PrivateKey.randomKeypair();

function createSignatureCredential<Data>(type: NestedProvable, data: Data) {
  let issuer = PrivateKey.randomKeypair();
  let signature = Signature.create(
    issuer.privateKey,
    NestedProvable.get(Credential.type(type)).toFields({ owner, data })
  );
  return {
    credential: { owner, data },
    private: { issuerPublicKey: issuer.publicKey, issuerSignature: signature },
  };
}
