import { Field, PrivateKey, PublicKey, Signature } from 'o1js';
import { type NestedProvableFor } from '../src/nested.ts';
import {
  type CredentialType,
  HashedCredential,
  signCredential,
} from '../src/credentials.ts';

export { createSignatureCredential, createOwnerSignature, owner, ownerKey };

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

function createOwnerSignature<Private, Data>(
  context: Field,
  ...credentials: [
    CredentialType<any, Private, Data>,
    {
      credential: { owner: PublicKey; data: Data };
      private: Private;
    }
  ][]
) {
  // TODO support many credentials
  let [credentialType, credential] = credentials[0]!;
  return signCredential(ownerKey, {
    context,
    credentialType: credentialType,
    credential: credential.credential,
    privateInput: credential.private,
  });
}
