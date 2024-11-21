import {
  PublicKey,
  Signature,
  Undefined,
  Field,
  type ProvableHashable,
  Hashed,
  PrivateKey,
  Group,
  Poseidon,
} from 'o1js';
import {
  type InferNestedProvable,
  NestedProvable,
  type NestedProvableFor,
} from './nested.ts';
import { zip } from './util.ts';
import { hashDynamic } from './credentials/dynamic-hash.ts';
import { Schema } from './credentials/schema.ts';

export {
  type Credential,
  type CredentialSpec,
  type CredentialType,
  type CredentialInputs,
  type CredentialOutputs,
  hashCredential,
  verifyCredentials,
  signCredentials,
  type StoredCredential,
  defineCredential,
  withOwner,
  Unsigned,
  unsafeMissingOwner,
  createUnsigned,
  HashableCredential,
};

/**
 * A credential is a generic piece of data (the "attributes") along with an owner represented by a public key.
 */
type Credential<Data> = { owner: PublicKey; data: Data };

/**
 * The different types of credential we currently support.
 */
type CredentialType = 'unsigned' | 'simple' | 'recursive';

/**
 * A credential type is:
 * - a string id fully identifying the credential type
 * - a type for private parameters
 * - a type for data (which is left generic when defining credential types)
 * - a function `verify(...)` that verifies the credential inside a ZkProgram circuit
 * - a function `verifyOutsideCircuit(...)` that verifies the credential in normal JS
 * - a function `issuer(...)` that derives a commitment to the "issuer" of the credential, e.g. a public key for signed credentials
 */
type CredentialSpec<
  Type extends CredentialType = CredentialType,
  Witness = any,
  Data = any
> = {
  type: 'credential';
  credentialType: Type;
  witness: NestedProvableFor<Witness>;
  data: NestedProvableFor<Data>;

  verify(witness: Witness, credHash: Hashed<Credential<Data>>): void;

  verifyOutsideCircuit(
    witness: Witness,
    credHash: Hashed<Credential<Data>>
  ): Promise<void>;

  issuer(witness: Witness): Field;
};

/**
 * Credential in stored form, including the witness and metadata.
 */
type StoredCredential<Data = any, Witness = any, Metadata = any> = {
  version: 'v0';
  witness: Witness;
  metadata: Metadata;
  credential: Credential<Data>;
};

/**
 * Hash a credential.
 */
function hashCredential<Data>(credential: Credential<Data>) {
  let type = Schema.type(credential);
  return Hashed.create(type, credentialHash).hash(type.fromValue(credential));
}

/**
 * Hash a credential inside a zk circuit.
 *
 * The differences to `hashCredential()` are:
 * - we have a dataType given which defines the circuit and therefore shouldn't be derived from the credential
 * - we can't convert the credential data from plain JS values
 */
function hashCredentialInCircuit<Data>(
  dataType: NestedProvableFor<Data>,
  credential: Credential<Data>
) {
  let type = NestedProvable.get(withOwner(dataType));
  return Hashed.create(type, credentialHash).hash(credential);
}

/**
 * Inputs to verify credentials inside a presentation proof.
 */
type CredentialInputs = {
  context: Field;
  ownerSignature: Signature;

  credentials: {
    spec: CredentialSpec;
    credential: Credential<any>;
    witness: any;
  }[];
};

/**
 * Outputs of verifying credentials, used as inputs to application circuit.
 */
type CredentialOutputs = {
  owner: PublicKey;
  credentials: {
    credential: Credential<any>;
    issuer: Field;
  }[];
};

function verifyCredentials({
  context,
  ownerSignature,
  credentials,
}: CredentialInputs): CredentialOutputs {
  // pack credentials in hashes
  let credHashes = credentials.map(({ spec: { data }, credential }) =>
    hashCredentialInCircuit(data, credential)
  );

  // verify each credential using its own verification method
  zip(credentials, credHashes).forEach(([{ spec, witness }, credHash]) => {
    spec.verify(witness, credHash);
  });

  // create issuer hashes for each credential
  // TODO would be nice to make this a `Hashed<Issuer>` over a more informative `Issuer` type, for easier use in the app circuit
  let issuers = credentials.map(({ spec, witness }) => spec.issuer(witness));

  // assert that all credentials have the same owner, and determine that owner
  let owner: undefined | PublicKey;

  credentials.forEach(({ credential }) => {
    owner ??= credential.owner; // set to the first owner
    credential.owner.assertEquals(owner);
  });

  // verify the owner signature
  if (owner !== undefined) {
    let hashes = credHashes.map((c) => c.hash);
    let ok = ownerSignature.verify(owner, [
      context,
      ...zip(hashes, issuers).flat(),
    ]);
    ok.assertTrue('Invalid owner signature');
  }

  return {
    owner: owner ?? PublicKey.empty(), // use a (0,0) public key in case there are no credentials

    // credential-issuer pairs
    credentials: zip(credentials, issuers).map(([{ credential }, issuer]) => ({
      credential,
      issuer,
    })),
  };
}

function signCredentials<Private, Data>(
  ownerKey: PrivateKey,
  context: Field,
  ...credentials: {
    credentialType: CredentialSpec<any, Private, Data>;
    credential: Credential<Data>;
    witness: Private;
  }[]
) {
  let hashes = credentials.map(
    ({ credential }) => hashCredential(credential).hash
  );
  let issuers = credentials.map(({ credentialType, witness }) =>
    credentialType.issuer(witness)
  );
  return Signature.create(ownerKey, [context, ...zip(hashes, issuers).flat()]);
}

function defineCredential<
  Type extends CredentialType,
  Witness extends NestedProvable
>(config: {
  credentialType: Type;
  witness: Witness;

  verify<Data>(
    witness: InferNestedProvable<Witness>,
    credHash: Hashed<Credential<Data>>
  ): void;

  verifyOutsideCircuit<Data>(
    witness: InferNestedProvable<Witness>,
    credHash: Hashed<Credential<Data>>
  ): Promise<void>;

  issuer(witness: InferNestedProvable<Witness>): Field;
}) {
  return function credential<DataType extends NestedProvable>(
    dataType: DataType
  ): CredentialSpec<
    Type,
    InferNestedProvable<Witness>,
    InferNestedProvable<DataType>
  > {
    return {
      type: 'credential',
      credentialType: config.credentialType,
      witness: config.witness as any,
      data: dataType as any,
      verify: config.verify,
      verifyOutsideCircuit: config.verifyOutsideCircuit,
      issuer: config.issuer,
    };
  };
}

// dummy credential with no proof attached
type Unsigned<Data> = StoredCredential<Data, undefined, undefined>;

const Unsigned = defineCredential({
  credentialType: 'unsigned',
  witness: Undefined,

  // do nothing
  verify() {},
  async verifyOutsideCircuit() {},

  // dummy issuer
  issuer() {
    return Field(0);
  },
});

function unsafeMissingOwner(): PublicKey {
  return PublicKey.fromGroup(Group.generator);
}

function createUnsigned<Data>(data: Data): Unsigned<Data> {
  return {
    version: 'v0',
    metadata: undefined,
    credential: { owner: unsafeMissingOwner(), data },
    witness: undefined,
  };
}

function credentialHash({ owner, data }: Credential<unknown>) {
  let ownerHash = Poseidon.hash(owner.toFields());
  let dataHash = hashDynamic(data);
  return Poseidon.hash([ownerHash, dataHash]);
}

// helpers to create derived types

function withOwner<DataType extends NestedProvable>(data: DataType) {
  return { owner: PublicKey, data };
}

function HashableCredential<Data>(
  dataType: NestedProvableFor<Data>
): ProvableHashable<Credential<Data>> {
  return NestedProvable.get(withOwner(dataType));
}
