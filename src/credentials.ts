import {
  assert,
  Field,
  Provable,
  PublicKey,
  Signature,
  Struct,
  Undefined,
  VerificationKey,
  type ProvablePure,
  DynamicProof,
  type InferProvable,
  FeatureFlags,
  Proof,
} from 'o1js';
import {
  type InferProvableType,
  type ProvablePureType,
  ProvableType,
} from './o1js-missing.ts';
import {
  type InferNestedProvable,
  NestedProvable,
  type NestedProvablePure,
  type NestedProvablePureFor,
} from './nested.ts';

export { Credential, type CredentialId };

const Undefined_: ProvablePure<undefined> = Undefined;

type CredentialId = 'none' | 'signatureNative' | 'proof';

/**
 * A credential is:
 * - a string fully identifying the credential type
 * - a type for public parameters
 * - a type for private parameters
 * - a type for data (which is left generic when defining credential types)
 * - a function `verify(publicInput: Public, privateInput: Private, data: Data)` that asserts the credential is valid
 */
type Credential<Id extends CredentialId, Public, Private, Data> = {
  type: 'credential';
  id: Id;
  public: ProvablePureType<Public>;
  private: ProvableType<Private>;
  data: NestedProvablePureFor<Data>;

  verify(publicInput: Public, privateInput: Private, data: Data): void;
};

function defineCredential<
  Id extends CredentialId,
  PublicType extends ProvablePureType,
  PrivateType extends ProvableType
>(config: {
  id: Id;
  public: PublicType;
  private: PrivateType;

  verify<DataType extends NestedProvablePure>(
    publicInput: InferProvableType<PublicType>,
    privateInput: InferProvableType<PrivateType>,
    dataType: DataType,
    data: InferNestedProvable<DataType>
  ): void;
}) {
  return function credential<DataType extends NestedProvablePure>(
    dataType: DataType
  ): Credential<
    Id,
    InferProvableType<PublicType>,
    InferProvableType<PrivateType>,
    InferNestedProvable<DataType>
  > {
    return {
      type: 'credential',
      id: config.id,
      public: config.public,
      private: config.private,
      data: dataType as any,
      verify(publicInput, privateInput, data) {
        return config.verify(publicInput, privateInput, dataType, data);
      },
    };
  };
}

// dummy credential with no proof attached
const None = defineCredential({
  id: 'none',
  public: Undefined_,
  private: Undefined_,
  verify() {
    // do nothing
  },
});

// native signature
const Signed = defineCredential({
  id: 'signatureNative',
  public: PublicKey, // issuer public key
  private: Signature,

  // verify the signature
  verify(issuerPk, signature, type, data) {
    let ok = signature.verify(
      issuerPk,
      NestedProvable.get(type).toFields(data)
    );
    assert(ok, 'Invalid signature');
  },
});

// TODO include hash of public inputs of the inner proof
// TODO maybe names could be issuer, credential
function Proved<
  DataType extends NestedProvablePure,
  InputType extends ProvablePureType,
  Data extends InferNestedProvable<DataType>,
  Input extends InferProvable<InputType>
>(
  Proof: typeof DynamicProof<Input, Data>,
  dataType: DataType
): Credential<
  'proof',
  Field,
  {
    vk: VerificationKey;
    proof: DynamicProof<Input, Data>;
  },
  InferNestedProvable<DataType>
> {
  let type = NestedProvable.get(dataType);
  return {
    type: 'credential',
    id: 'proof',
    public: Field, // the verification key hash (TODO: make this a `VerificationKey` when o1js supports it)
    private: Struct({ vk: VerificationKey, proof: Proof }),
    data: type,
    verify(vkHash, { vk, proof }, data) {
      vk.hash.assertEquals(vkHash);
      proof.verify(vk);
      Provable.assertEqual(type, proof.publicOutput, data);
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
      publicOutputType: DataType;
      analyzeMethods: () => Promise<{
        [I in keyof any]: any;
      }>;
    };
  },
  // TODO this needs to be exposed on the program!!
  maxProofsVerified: 0 | 1 | 2 = 0
) {
  const featureFlags = await FeatureFlags.fromZkProgram(program);

  class InputProof extends DynamicProof<Input, Data> {
    static publicInputType = program.publicInputType;
    static publicOutputType = program.publicOutputType;
    static maxProofsVerified = maxProofsVerified;
    static featureFlags = featureFlags;
  }

  return Object.assign(
    Proved<DataType, InputType, Data, Input>(
      InputProof,
      program.publicOutputType
    ),
    {
      fromProof(proof: Proof<Input, Data>): DynamicProof<Input, Data> {
        return InputProof.fromProof(proof as any);
      },
      dummyProof(
        publicInput: Input,
        publicOutput: Data
      ): Promise<DynamicProof<Input, Data>> {
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
