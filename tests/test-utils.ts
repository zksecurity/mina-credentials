import { Field, PrivateKey } from 'o1js';
import {
  type Credential,
  type CredentialType,
  signCredentials,
} from '../src/credential.ts';

export { createOwnerSignature, owner, ownerKey, issuer, issuerKey };

const { publicKey: owner, privateKey: ownerKey } = PrivateKey.randomKeypair();
const { publicKey: issuer, privateKey: issuerKey } = PrivateKey.randomKeypair();

function createOwnerSignature<Witness, Data>(
  context: Field,
  ...credentials: [
    CredentialType<any, Witness, Data>,
    { credential: Credential<Data>; witness: Witness }
  ][]
) {
  return signCredentials(
    ownerKey,
    context,
    ...credentials.map(([credentialType, cred]) => ({
      ...cred,
      credentialType,
    }))
  );
}
