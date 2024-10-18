import { Field, PrivateKey, PublicKey } from 'o1js';
import { type CredentialType, signCredential } from '../src/credentials.ts';

export { createOwnerSignature, owner, ownerKey, issuer, issuerKey };

const { publicKey: owner, privateKey: ownerKey } = PrivateKey.randomKeypair();
const { publicKey: issuer, privateKey: issuerKey } = PrivateKey.randomKeypair();

function createOwnerSignature<Witness, Data>(
  context: Field,
  ...credentials: [
    CredentialType<any, Witness, Data>,
    {
      credential: { owner: PublicKey; data: Data };
      witness: Witness;
    }
  ][]
) {
  // TODO support many credentials
  let [credentialType, credential] = credentials[0]!;
  return signCredential(ownerKey, {
    context,
    credentialType: credentialType,
    credential: credential.credential,
    witness: credential.witness,
  });
}
