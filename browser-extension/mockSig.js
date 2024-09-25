import { PrivateKey, PublicKey, Signature, Field } from 'o1js';

const privateKey = PrivateKey.random();

const publicKey = privateKey.toPublicKey();

const age = Field(25);
const message = [age];

const signature = Signature.create(privateKey, message);

console.log('Private Key:', privateKey.toBase58());
console.log('Public Key:', publicKey.toBase58());
console.log('Signature:', signature.toBase58());
