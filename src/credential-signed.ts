/**
 * Native signature credential
 */
import { Poseidon, PrivateKey, PublicKey, Signature } from 'o1js';
import {
  type StoredCredential,
  type Credential,
  defineCredential,
  hashCredential,
} from './credential.ts';
import { NestedProvable } from './nested.ts';
import { prefixes } from './constants.ts';
import { ProvableType } from './o1js-missing.ts';
import { deserializeNestedProvableValue } from './serialize-provable.ts';

export { Signed, createSigned, type Witness, type Metadata };

type Witness = {
  type: 'simple';
  issuer: PublicKey;
  issuerSignature: Signature;
};

// TODO
type Metadata = undefined;

type Signed<Data> = StoredCredential<Data, Witness, Metadata>;

const Signed = Object.assign(
  defineCredential({
    credentialType: 'simple',
    witness: {
      type: ProvableType.constant('simple' as const),
      issuer: PublicKey,
      issuerSignature: Signature,
    },

    // verify the signature
    verify({ issuer, issuerSignature }, credHash) {
      let ok = issuerSignature.verify(issuer, [credHash.hash]);
      ok.assertTrue('Invalid signature');
    },
    async verifyOutsideCircuit({ issuer, issuerSignature }, credHash) {
      let ok = issuerSignature.verify(issuer, [credHash.hash]);
      ok.assertTrue('Invalid signature');
    },

    // issuer == issuer public key
    issuer({ issuer }) {
      return Poseidon.hashWithPrefix(prefixes.issuerSimple, issuer.toFields());
    },

    matchesSpec(witness) {
      return witness.type === 'simple';
    },
  }),
  {
    issuer(issuer: PublicKey) {
      return Poseidon.hashWithPrefix(prefixes.issuerSimple, issuer.toFields());
    },
  }
);

function createSigned<Data>(
  issuerPrivateKey: PrivateKey,
  credentialInput: Credential<Data> | string
): Signed<Data> {
  let issuer = issuerPrivateKey.toPublicKey();
  let credential =
    typeof credentialInput === 'string'
      ? deserializeNestedProvableValue(JSON.parse(credentialInput))
      : credentialInput;
  let credHash = hashCredential(credential);
  let issuerSignature = Signature.create(issuerPrivateKey, [credHash.hash]);

  return {
    version: 'v0',
    witness: { type: 'simple', issuer, issuerSignature },
    metadata: undefined,
    credential,
  };
}
