import {
  Provable,
  VerificationKey,
  type ProvablePure,
  DynamicProof,
  type InferProvable,
  FeatureFlags,
  Proof,
  Poseidon,
} from 'o1js';
import {
  assertPure,
  ProvableType,
  type ProvablePureType,
} from './o1js-missing.ts';
import {
  type InferNestedProvable,
  NestedProvable,
  type NestedProvablePure,
  type NestedProvablePureFor,
} from './nested.ts';
import { prefixes } from './constants.ts';
import {
  type CredentialSpec,
  type Credential,
  type StoredCredential,
  HashableCredential,
} from './credential.ts';

export { Recursive };

type Witness<Data, Input> = {
  type: 'recursive';
  vk: VerificationKey;
  proof: DynamicProof<Input, Credential<Data>>;
};

type Recursive<Data, Input> = StoredCredential<
  Data,
  Witness<Data, Input>,
  undefined
>;

function Recursive<
  DataType extends NestedProvablePure,
  InputType extends ProvablePureType,
  Data extends InferNestedProvable<DataType>,
  Input extends InferProvable<InputType>
>(
  Proof: typeof DynamicProof<Input, Credential<Data>>,
  dataType: DataType
): CredentialSpec<'recursive', Witness<Data, Input>, Data> {
  // TODO annoying that this cast doesn't work without overriding the type
  let data: NestedProvablePureFor<Data> = dataType as any;
  const credentialType = HashableCredential(data);

  return {
    type: 'credential',
    credentialType: 'recursive',
    witness: {
      type: ProvableType.constant('recursive' as const),
      vk: VerificationKey,
      proof: Proof,
    },
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

Recursive.fromProgram = RecursiveFromProgram;

async function RecursiveFromProgram<
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
    Recursive<ProvablePure<Data>, InputType, Data, Input>(InputProof, dataType),
    {
      program,

      async create(inputs: AllInputs): Promise<Recursive<Data, Input>> {
        let vk = await this.compile();
        let proof = InputProof.fromProof(await programWrapper.run(inputs));
        return {
          version: 'v0',
          metadata: undefined,
          credential: proof.publicOutput,
          witness: { type: 'recursive', vk, proof },
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

      async dummy(
        credential: Credential<Data>
      ): Promise<Recursive<Data, Input>> {
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
          witness: { type: 'recursive', vk, proof: dummyProof },
        };
      },
    }
  );
}
