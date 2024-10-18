import {
  assert,
  Provable,
  PublicKey,
  Signature,
  Undefined,
  VerificationKey,
  type ProvablePure,
  DynamicProof,
  type InferProvable,
  FeatureFlags,
  Proof,
  Field,
  type ProvableHashable,
  Hashed,
  Poseidon,
  PrivateKey,
  Group,
} from 'o1js';
import {
  assertPure,
  ProvableType,
  type ProvablePureType,
} from './o1js-missing.ts';
import {
  type InferNestedProvable,
  NestedProvable,
  type NestedProvableFor,
  type NestedProvablePure,
  type NestedProvablePureFor,
} from './nested.ts';
import { zip } from './util.ts';
import { prefixes } from './constants.ts';

export {
  type Credential,
  type CredentialType,
  type CredentialId,
  type CredentialInputs,
  hashCredential,
  verifyCredentials,
  signCredential,
  type StoredCredential,
  defineCredential,
  withOwner,
  Unsigned,
  unsafeMissingOwner,
  createUnsigned,
  Proved,
  ProvedFromProgram,
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
type StoredCredential<Data, Witness, Metadata> = {
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

// TODO support many credentials
function signCredential<Private, Data>(
  ownerKey: PrivateKey,
  inputs: {
    credentialType: CredentialType<any, Private, Data>;
    context: Field;
    credential: Credential<Data>;
    witness: Private;
  }
) {
  let { credentialType, context, credential, witness } = inputs;
  let credHash = HashedCredential(credentialType.data).hash(credential);
  let issuer = credentialType.issuer(witness);
  return Signature.create(ownerKey, [context, credHash.hash, issuer]);
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

type Proved<Data, Input> = StoredCredential<
  Data,
  { vk: VerificationKey; proof: DynamicProof<Input, Credential<Data>> },
  undefined
>;

function Proved<
  DataType extends NestedProvablePure,
  InputType extends ProvablePureType,
  Data extends InferNestedProvable<DataType>,
  Input extends InferProvable<InputType>
>(
  Proof: typeof DynamicProof<Input, Credential<Data>>,
  dataType: DataType
): CredentialType<
  'proof',
  {
    vk: VerificationKey;
    proof: DynamicProof<Input, Credential<Data>>;
  },
  Data
> {
  // TODO annoying that this cast doesn't work without overriding the type
  let data: NestedProvablePureFor<Data> = dataType as any;
  const credentialType = HashableCredential(data);

  return {
    type: 'credential',
    id: 'proof',
    witness: { vk: VerificationKey, proof: Proof },
    data: NestedProvable.get(data),

    // verify the proof, check that its public output is exactly the credential
    verify({ vk, proof }, credHash) {
      proof.verify(vk);
      let credential = credHash.unhash();
      Provable.assertEqual(credentialType, proof.publicOutput, credential);
    },

    // issuer == hash of vk and public input
    issuer({ vk, proof }) {
      let credIdent = Poseidon.hash(
        Proof.publicInputType.toFields(proof.publicInput)
      );
      return Poseidon.hashWithPrefix(prefixes.issuerRecursive, [
        vk.hash,
        credIdent,
      ]);
    },
  };
}

async function ProvedFromProgram<
  DataType extends ProvablePure<any>,
  InputType extends ProvablePure<any>,
  Data extends InferNestedProvable<DataType>,
  Input extends InferProvable<InputType>,
  AllInputs
>(
  programWrapper: {
    program: {
      publicInputType: InputType;
      publicOutputType: ProvablePure<Credential<Data>>;
      analyzeMethods(): Promise<{
        [I in keyof any]: any;
      }>;
    };
    compile(): Promise<VerificationKey>;
    run(inputs: AllInputs): Promise<Proof<Input, Credential<Data>>>;
  },
  // TODO this needs to be exposed on the program!!
  maxProofsVerified: 0 | 1 | 2 = 0
) {
  let { program } = programWrapper;
  const featureFlags = await FeatureFlags.fromZkProgram(program);

  class InputProof extends DynamicProof<Input, Credential<Data>> {
    static publicInputType = program.publicInputType;
    static publicOutputType = program.publicOutputType;
    static maxProofsVerified = maxProofsVerified;
    static featureFlags = featureFlags;
  }

  let data = ProvableType.synthesize(program.publicOutputType).data;
  let dataType = NestedProvable.get(NestedProvable.fromValue(data));
  assertPure(dataType);

  let isCompiled = false;
  let vk: VerificationKey | undefined;

  return Object.assign(
    Proved<ProvablePure<Data>, InputType, Data, Input>(InputProof, dataType),
    {
      program,

      async create(inputs: AllInputs): Promise<Proved<Data, Input>> {
        let vk = await this.compile();
        let proof = await programWrapper.run(inputs);
        return {
          version: 'v0',
          metadata: undefined,
          credential: proof.publicOutput,
          witness: { vk, proof: InputProof.fromProof(proof) },
        };
      },

      async compile() {
        if (isCompiled) return vk!;
        vk = await programWrapper.compile();
        isCompiled = true;
        return vk;
      },

      fromProof(
        proof: Proof<Input, Credential<Data>>
      ): DynamicProof<Input, Credential<Data>> {
        return InputProof.fromProof(proof as any);
      },

      async dummy(credential: Credential<Data>): Promise<Proved<Data, Input>> {
        let input = ProvableType.synthesize(program.publicInputType);
        let vk = await this.compile();

        let dummyProof = await InputProof.dummy(
          input,
          credential,
          maxProofsVerified
        );
        return {
          version: 'v0',
          metadata: undefined,
          credential,
          witness: { vk, proof: dummyProof },
        };
      },
    }
  );
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
