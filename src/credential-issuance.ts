/**
 * Native signature credential
 */
import { Poseidon, PrivateKey, PublicKey, Signature } from 'o1js';
import {
  type StoredCredential,
  type Credential,
  defineCredential,
  hashCredential,
} from './credentials.ts';
import { NestedProvable } from './nested.ts';
import { prefixes } from './constants.ts';
import { ProvableType } from './o1js-missing.ts';

export {
  SignedCredential,
  createSignedCredential,
  type Witness,
  type Metadata,
};

type Witness = {
  type: 'simple';
  issuer: PublicKey;
  issuerSignature: Signature;
};

// TODO
type Metadata = undefined;

type SignedCredential<Data> = StoredCredential<Data, Witness, Metadata>;

const SignedCredential = defineCredential({
  id: 'signature-native',
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

  // issuer == issuer public key
  issuer({ issuer }) {
    return Poseidon.hashWithPrefix(prefixes.issuerSimple, issuer.toFields());
  },
});

function createSignedCredential<Data>(
  issuerPrivateKey: PrivateKey,
  credential: Credential<Data>
): SignedCredential<Data> {
  let issuer = issuerPrivateKey.toPublicKey();
  let dataType = NestedProvable.fromValue(credential.data);
  let credHash = hashCredential(dataType, credential);
  let issuerSignature = Signature.create(issuerPrivateKey, [credHash.hash]);

  return {
    version: 'v0',
    witness: { type: 'simple', issuer, issuerSignature },
    metadata: undefined,
    credential,
  };
}
