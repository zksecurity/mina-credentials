/**
 * Wallet that is stored in local storage
 *
 * Simplifies the demo for users that don't have a compatible wallet
 */
import { PrivateKey } from 'o1js';

export { privateKey, publicKey };

// create or load private key from local storage
let privateKeyBase58 = localStorage.getItem('privateKey');

if (privateKeyBase58 === null) {
  privateKeyBase58 = PrivateKey.random().toBase58();
  localStorage.setItem('privateKey', privateKeyBase58);
}

const privateKey = PrivateKey.fromBase58(privateKeyBase58);
const publicKey = privateKey.toPublicKey();
