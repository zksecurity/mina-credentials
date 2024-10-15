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
  provable,
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

export {
  Credential,
  type CredentialType,
  type CredentialId,
  type CredentialFor,
};

const Undefined_: ProvablePure<undefined> = Undefined;

type CredentialId = 'none' | 'signature-native' | 'proof';

/**
 * A credential type is:
 * - a string fully identifying the credential type
 * - a type for private parameters
 * - a type for data (which is left generic when defining credential types)
 * - a function `verify(publicInput: Public, privateInput: Private, data: Data)` that asserts the credential is valid
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

  verify(privateInput: Private, credential: Credential<Data>): void;
};

type Credential<Data> = { owner: PublicKey; data: Data };

type CredentialFor<C extends CredentialType> = C extends CredentialType<
  CredentialId,
  any,
  infer Data
>
  ? Credential<Data>
  : never;

function defineCredential<
  Id extends CredentialId,
  PrivateType extends NestedProvable
>(config: {
  id: Id;
  private: PrivateType;

  verify<DataType extends NestedProvablePure>(
    privateInput: InferNestedProvable<PrivateType>,
    Credential: { owner: typeof PublicKey; data: DataType },
    credential: Credential<InferNestedProvable<DataType>>
  ): void;
}) {
  return function credential<DataType extends NestedProvablePure>(
    dataType: DataType
  ): CredentialType<
    Id,
    InferNestedProvable<PrivateType>,
    InferNestedProvable<DataType>
  > {
    const Credential = { owner: PublicKey, data: dataType };
    return {
      type: 'credential',
      id: config.id,
      private: config.private as any,
      data: dataType as any,
      verify(privateInput, credential) {
        return config.verify(privateInput, Credential, credential);
      },
    };
  };
}

// dummy credential with no proof attached
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
  verify({ issuerPublicKey, issuerSignature }, Credential, credential) {
    let ok = issuerSignature.verify(
      issuerPublicKey,
      NestedProvable.get(Credential).toFields(credential)
    );
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
  let type = NestedProvable.get(dataType);
  const Credential = provable({ owner: PublicKey, data: type });
  return {
    type: 'credential',
    id: 'proof',
    private: { vk: VerificationKey, proof: Proof },
    data: type,

    verify({ vk, proof }, credential) {
      proof.verify(vk);
      Provable.assertEqual(Credential, proof.publicOutput, credential);
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
      publicOutputType: ProvablePure<{ owner: PublicKey; data: Data }>;
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
  let dataType = ProvableType.fromValue(data);
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
};
