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

export {
  Credential,
  type CredentialType,
  type CredentialId,
  type CredentialInputs,
  verifyCredentials,
};

export { HashedCredential };

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
 */
type CredentialType<
  Id extends CredentialId = CredentialId,
  Private = any,
  Data = any
> = {
  type: 'credential';
  id: Id;
  private: NestedProvableFor<Private>;
  data: NestedProvablePureFor<Data>;

  verify(privateInput: Private, credHash: Hashed<Credential<Data>>): void;
};

/**
 * Inputs to verify credentials inside a presentation proof.
 */
type CredentialInputs = {
  context: Field;
  ownerSignature: Signature;

  credentials: {
    credentialType: CredentialType;
    credential: Credential<any>;
    privateInput: any;
  }[];
};

function verifyCredentials({
  context,
  ownerSignature,
  credentials,
}: CredentialInputs) {
  // pack credentials in hashes
  let credHashes: Hashed<Credential<any>>[] = credentials.map(
    ({ credentialType: { data }, credential }) =>
      HashedCredential(data).hash(credential)
  );

  // verify each credential using its own verification method
  zip(credentials, credHashes).forEach(
    ([{ credentialType, privateInput }, credHash]) => {
      credentialType.verify(privateInput, credHash);
    }
  );

  // TODO derive `issuer` in a credential-specific way, for every credential
  // TODO if there are any credentials: assert all have the same `owner`
  // TODO if there are any credentials: use `context` from public inputs and `ownerSignature` from private inputs to verify owner signature
}

function defineCredential<
  Id extends CredentialId,
  PrivateType extends NestedProvable
>(config: {
  id: Id;
  private: PrivateType;

  verify<Data>(
    privateInput: InferNestedProvable<PrivateType>,
    credHash: Hashed<Credential<Data>>
  ): void;
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
      private: config.private as any,
      data: dataType as any,
      verify: config.verify,
    };
  };
}

// dummy credential with no proof attached
const Undefined_: ProvablePure<undefined> = Undefined;

const None = defineCredential({
  id: 'none',
  private: Undefined_,
  verify() {
    // do nothing
  },
});

// native signature
const Signed = defineCredential({
  id: 'signature-native',
  private: {
    issuerPublicKey: PublicKey,
    issuerSignature: Signature,
  },

  // verify the signature
  verify({ issuerPublicKey, issuerSignature }, credHash) {
    let ok = issuerSignature.verify(issuerPublicKey, [credHash.hash]);
    assert(ok, 'Invalid signature');
  },
});

// TODO include hash of public inputs of the inner proof
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
    private: { vk: VerificationKey, proof: Proof },
    data: NestedProvable.get(data),

    verify({ vk, proof }, credHash) {
      proof.verify(vk);
      let credential = credHash.unhash();
      Provable.assertEqual(credentialType, proof.publicOutput, credential);
    },
  };
}

async function ProvedFromProgram<
  DataType extends ProvablePure<any>,
  InputType extends ProvablePure<any>,
  Data extends InferNestedProvable<DataType>,
  Input extends InferProvable<InputType>
>(
  {
    program,
  }: {
    program: {
      publicInputType: InputType;
      publicOutputType: ProvablePure<Credential<Data>>;
      analyzeMethods: () => Promise<{
        [I in keyof any]: any;
      }>;
    };
  },
  // TODO this needs to be exposed on the program!!
  maxProofsVerified: 0 | 1 | 2 = 0
) {
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

  return Object.assign(
    Proved<ProvablePure<Data>, InputType, Data, Input>(InputProof, dataType),
    {
      fromProof(
        proof: Proof<Input, Credential<Data>>
      ): DynamicProof<Input, Credential<Data>> {
        return InputProof.fromProof(proof as any);
      },
      dummyProof(
        publicInput: Input,
        publicOutput: Credential<Data>
      ): Promise<DynamicProof<Input, Credential<Data>>> {
        return InputProof.dummy(
          publicInput,
          publicOutput as any,
          maxProofsVerified
        );
      },
    }
  );
}

const Credential = {
  none: None,
  proof: Proved,
  proofFromProgram: ProvedFromProgram,
  signatureNative: Signed,

  // type layout of a credential
  withOwner<DataType extends NestedProvable>(data: DataType) {
    return { owner: PublicKey, data };
  },
};

// helpers to create derived types

function HashableCredential<Data>(
  dataType: NestedProvableFor<Data>
): ProvableHashable<Credential<Data>> {
  return NestedProvable.get(Credential.withOwner(dataType)) as any;
}

function HashedCredential<Data>(
  dataType: NestedProvableFor<Data>
): typeof Hashed<Credential<Data>> {
  return Hashed.create(HashableCredential(dataType));
}
