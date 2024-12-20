import { Field, PrivateKey } from 'o1js';
import {
  type Credential,
  type CredentialSpec,
  signCredentials,
} from '../src/credential.ts';

export {
  createOwnerSignature,
  randomPublicKey,
  owner,
  ownerKey,
  issuer,
  issuerKey,
  zkAppAddress,
};

const { publicKey: owner, privateKey: ownerKey } = PrivateKey.randomKeypair();
const { publicKey: issuer, privateKey: issuerKey } = PrivateKey.randomKeypair();

export const zkAppContext = {
  address: 'B62qiV4KJMMfAuUCs1b8T3RMRJrLk3paXcEPkLz9jbga1zKP782NmBA',
  tokenId: '1',
  network: 'mainnet',
};

const zkAppAddress = JSON.stringify(zkAppContext);

function randomPublicKey() {
  return PrivateKey.random().toPublicKey();
}

function createOwnerSignature<Witness, Data>(
  context: Field,
  ...credentials: [
    CredentialSpec<any, Witness, Data>,
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
