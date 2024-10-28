import { type PublicKey } from 'o1js';
import {
  createUnsigned,
  type CredentialSpec,
  type CredentialType,
  hashCredential,
  type StoredCredential,
  Unsigned,
} from './credential.ts';
import {
  createSigned,
  Signed,
  type Witness as SignedWitness,
} from './credential-signed.ts';
import {
  Recursive,
  type Witness as RecursiveWitness,
} from './credential-recursive.ts';
import { assert, hasProperty } from './util.ts';
import {
  type InferNestedProvable,
  NestedProvable,
  type NestedProvablePure,
} from './nested.ts';
import { assertPure } from './o1js-missing.ts';
import { serializeNestedProvableValue } from './serialize-spec.ts';
import { deserializeNestedProvableValue } from './deserialize-spec.ts';

export { Credential, validateCredential };

/**
 * A credential is a generic piece of data (the "attributes") along with an owner represented by a public key.
 */
type Credential<Data> = { owner: PublicKey; data: Data };

const Credential = {
  Unsigned,
  Simple: Signed,
  Recursive,

  /**
   * Issue a "simple" signed credential.
   */
  sign: createSigned,

  /**
   * Create a dummy credential with no owner and no signature.
   */
  unsigned: createUnsigned,

  /**
   * Serialize a credential to a JSON string.
   */
  toJSON(credential: StoredCredential) {
    let json = {
      version: credential.version,
      witness: serializeNestedProvableValue(credential.witness),
      metadata: credential.metadata,
      credential: serializeNestedProvableValue(credential.credential),
    };
    return JSON.stringify(json);
  },

  /**
   * Deserialize a credential from a JSON string.
   */
  fromJSON(json: string): StoredCredential {
    let obj = JSON.parse(json);
    return {
      version: obj.version,
      witness: deserializeNestedProvableValue(obj.witness),
      metadata: obj.metadata,
      credential: deserializeNestedProvableValue(obj.credential),
    };
  },

  /**
   * Validate a credential.
   */
  validate: validateCredential,
};

// validating generic credential

type Witness = SignedWitness | RecursiveWitness;

async function validateCredential(
  credential: StoredCredential<unknown, unknown, unknown>
) {
  assert(
    credential.version === 'v0',
    `Unsupported credential version: ${credential.version}`
  );

  assert(knownWitness(credential.witness), 'Unknown credential type');

  // TODO: this is brittle. probably data type should be part of metadata.
  let data = NestedProvable.get(
    NestedProvable.fromValue(credential.credential.data)
  );
  assertPure(data);
  let spec = getCredentialSpec(credential.witness)(data);

  let credHash = hashCredential(data, credential.credential);
  await spec.verifyOutsideCircuit(credential.witness, credHash);
}

const witnessTypes = new Set<unknown>([
  'simple',
  'recursive',
] satisfies Witness['type'][]);

function knownWitness(witness: unknown): witness is Witness {
  return hasProperty(witness, 'type') && witnessTypes.has(witness.type);
}

function getCredentialSpec<W extends Witness>(
  witness: W
): <DataType extends NestedProvablePure>(
  dataType: DataType
) => CredentialSpec<CredentialType, W, InferNestedProvable<DataType>> {
  switch (witness.type) {
    case 'simple':
      return Credential.Simple as any;
    case 'recursive':
      return Credential.Recursive.Generic as any;
  }
}
