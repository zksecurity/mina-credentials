import { PrivateKey, Signature } from 'o1js';
import { type NestedProvableFor } from '../src/nested.ts';
import { HashedCredential } from '../src/credentials.ts';

export { createSignatureCredential, owner, ownerKey };

const { publicKey: owner, privateKey: ownerKey } = PrivateKey.randomKeypair();

function createSignatureCredential<Data>(
  type: NestedProvableFor<Data>,
  data: Data
) {
  let issuer = PrivateKey.randomKeypair();
  let credHash = HashedCredential(type).hash({ owner, data });
  let signature = Signature.create(issuer.privateKey, [credHash.hash]);
  return {
    credential: { owner, data },
    private: { issuerPublicKey: issuer.publicKey, issuerSignature: signature },
  };
}
