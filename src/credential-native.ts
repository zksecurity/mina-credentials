/**
 * Native signature credential
 */
import { Poseidon, PrivateKey, PublicKey, Signature } from 'o1js';
import {
  type StoredCredential,
  type Credential,
  hashCredential,
  type CredentialSpec,
} from './credential.ts';
import {
  inferNestedProvable,
  type InferNestedProvable,
  NestedProvable,
} from './nested.ts';
import { prefixes } from './constants.ts';
import { ProvableType } from './o1js-missing.ts';
import { deserializeNestedProvableValue } from './serialize-provable.ts';
import type { JSONValue } from './types.ts';

export { Native, createNative, type Witness };

type Witness = {
  type: 'native';
  issuer: PublicKey;
  issuerSignature: Signature;
};

type Native<Data> = StoredCredential<Data, Witness>;

function Native<DataType extends NestedProvable>(
  dataType: DataType
): CredentialSpec<'native', Witness, InferNestedProvable<DataType>> {
  return {
    credentialType: 'native',
    witness: {
      type: ProvableType.constant('native' as const),
      issuer: PublicKey,
      issuerSignature: Signature,
    },
    data: inferNestedProvable(dataType),

    // verify the signature
    verify({ issuer, issuerSignature }, credHash) {
      let ok = issuerSignature.verify(issuer, [credHash]);
      ok.assertTrue('Invalid signature');
    },
    async verifyOutsideCircuit({ issuer, issuerSignature }, credHash) {
      let ok = issuerSignature.verify(issuer, [credHash]);
      ok.assertTrue('Invalid signature');
    },

    // issuer == issuer public key
    issuer({ issuer }) {
      return Poseidon.hashWithPrefix(prefixes.issuerNative, issuer.toFields());
    },

    matchesSpec(witness) {
      return witness.type === 'native';
    },
  };
}
Native.issuer = function (issuer: PublicKey) {
  return Poseidon.hashWithPrefix(prefixes.issuerNative, issuer.toFields());
};

function createNative<Data>(
  issuerPrivateKey: PrivateKey,
  credentialInput: Credential<Data> | string,
  metadata?: JSONValue
): Native<Data> {
  let issuer = issuerPrivateKey.toPublicKey();
  let credential =
    typeof credentialInput === 'string'
      ? deserializeNestedProvableValue(JSON.parse(credentialInput))
      : credentialInput;
  let credHash = hashCredential(credential);
  let issuerSignature = Signature.create(issuerPrivateKey, [credHash]);

  return {
    version: 'v0',
    witness: { type: 'native', issuer, issuerSignature },
    metadata,
    credential,
  };
}
