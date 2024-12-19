import { PrivateKey } from 'o1js';

export { getPrivateKey, getPublicKey };

const privateKey = PrivateKey.fromBase58(
  'EKDsgej3YrJriYnibHcEsJtYmoRsp2mzD2ta98EkvdNNLeXsrNB9'
);
const publicKey = privateKey.toPublicKey();

function getPrivateKey() {
  return privateKey;
}

function getPublicKey() {
  return publicKey;
}
