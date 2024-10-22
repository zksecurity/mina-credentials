import {
  PublicKey,
  Signature,
  Undefined,
  Field,
  type ProvableHashable,
  Hashed,
  PrivateKey,
  Group,
} from 'o1js';
import {
  type InferNestedProvable,
  NestedProvable,
  type NestedProvableFor,
  type NestedProvablePure,
  type NestedProvablePureFor,
} from './nested.ts';
import { zip } from './util.ts';

export {
  type Credential,
  type CredentialType,
  type CredentialId,
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
type CredentialId = 'none' | 'signature-native' | 'proof';

/**
 * A credential type is:
 * - a string id fully identifying the credential type
 * - a type for private parameters
 * - a type for data (which is left generic when defining credential types)
 * - a function `verify(...)` that asserts the credential is valid
 * - a function `issuer(...)` that derives a commitment to the "issuer" of the credential, e.g. a public key for signed credentials
 */
type CredentialType<
  Id extends CredentialId = CredentialId,
  Witness = any,
  Data = any
> = {
  type: 'credential';
  id: Id;
  witness: NestedProvableFor<Witness>;
  data: NestedProvablePureFor<Data>;

  verify(witness: Witness, credHash: Hashed<Credential<Data>>): void;

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

function hashCredential<Data>(
  dataType: NestedProvableFor<Data>,
  credential: Credential<Data>
) {
  return HashedCredential(dataType).hash(credential);
}

/**
 * Inputs to verify credentials inside a presentation proof.
 */
type CredentialInputs = {
  context: Field;
  ownerSignature: Signature;

  credentials: {
    credentialType: CredentialType;
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
  let credHashes = credentials.map(({ credentialType: { data }, credential }) =>
    hashCredential(data, credential)
  );

  // verify each credential using its own verification method
  zip(credentials, credHashes).forEach(
    ([{ credentialType, witness }, credHash]) => {
      credentialType.verify(witness, credHash);
    }
  );

  // create issuer hashes for each credential
  // TODO would be nice to make this a `Hashed<Issuer>` over a more informative `Issuer` type, for easier use in the app circuit
  let issuers = credentials.map(({ credentialType, witness }) =>
    credentialType.issuer(witness)
  );

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
    credentialType: CredentialType<any, Private, Data>;
    credential: Credential<Data>;
    witness: Private;
  }[]
) {
  let hashes = credentials.map(
    ({ credentialType: { data }, credential }) =>
      hashCredential(data, credential).hash
  );
  let issuers = credentials.map(({ credentialType, witness }) =>
    credentialType.issuer(witness)
  );
  return Signature.create(ownerKey, [context, ...zip(hashes, issuers).flat()]);
}

function defineCredential<
  Id extends CredentialId,
  PrivateType extends NestedProvable
>(config: {
  id: Id;
  witness: PrivateType;

  verify<Data>(
    witness: InferNestedProvable<PrivateType>,
    credHash: Hashed<Credential<Data>>
  ): void;

  issuer(witness: InferNestedProvable<PrivateType>): Field;
}) {
  return function credential<DataType extends NestedProvablePure>(
    dataType: DataType
  ): CredentialType<
    Id,
    InferNestedProvable<PrivateType>,
    InferNestedProvable<DataType>
  > {
    return {
      type: 'credential',
      id: config.id,
      witness: config.witness as any,
      data: dataType as any,
      verify: config.verify,
      issuer: config.issuer,
    };
  };
}

// dummy credential with no proof attached
type Unsigned<Data> = StoredCredential<Data, undefined, undefined>;

const Unsigned = defineCredential({
  id: 'none',
  witness: Undefined,

  // do nothing
  verify() {},

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

function withOwner<DataType extends NestedProvable>(data: DataType) {
  return { owner: PublicKey, data };
}

// helpers to create derived types

function HashableCredential<Data>(
  dataType: NestedProvableFor<Data>
): ProvableHashable<Credential<Data>> {
  return NestedProvable.get(withOwner(dataType)) as any;
}

function HashedCredential<Data>(
  dataType: NestedProvableFor<Data>
): typeof Hashed<Credential<Data>> {
  return Hashed.create(HashableCredential(dataType));
}
