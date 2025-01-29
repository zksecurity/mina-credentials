import {
  VerificationKey,
  type ProvablePure,
  DynamicProof,
  type InferProvable,
  FeatureFlags,
  Proof,
  Poseidon,
  verify,
  Cache,
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
  defineCredential,
  credentialHash,
  hashCredentialInCircuit,
} from './credential.ts';
import { assert } from './util.ts';

export { Recursive, type Witness };

type Witness<Data = any, Input = any> = {
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
  const data: NestedProvablePureFor<Data> = dataType as any;

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
      hashCredentialInCircuit(data, proof.publicOutput).hash.assertEquals(
        credHash.hash,
        'Invalid proof output'
      );
    },
    async verifyOutsideCircuit({ vk, proof }, credHash) {
      let ok = await verify(proof, vk);
      assert(ok, 'Invalid proof');
      hashCredentialInCircuit(data, proof.publicOutput).hash.assertEquals(
        credHash.hash,
        'Invalid proof output'
      );
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

const GenericRecursive = defineCredential({
  credentialType: 'recursive',
  witness: {
    type: ProvableType.constant('recursive'),
    vk: VerificationKey,
    proof: DynamicProof,
  },

  // verify the proof, check that its public output is exactly the credential
  verify({ vk, proof }, credHash) {
    proof.verify(vk);
    credentialHash(proof.publicOutput).assertEquals(
      credHash.hash,
      'Invalid proof output'
    );
  },
  async verifyOutsideCircuit({ vk, proof }, credHash) {
    let ok = await verify(proof, vk);
    assert(ok, 'Invalid proof');
    credentialHash(proof.publicOutput).assertEquals(
      credHash.hash,
      'Invalid proof output'
    );
  },

  // issuer == hash of vk and public input
  issuer({ vk, proof }) {
    let credIdent = Poseidon.hash(
      (proof.constructor as typeof DynamicProof).publicInputType.toFields(
        proof.publicInput
      )
    );
    return Poseidon.hashWithPrefix(prefixes.issuerRecursive, [
      vk.hash,
      credIdent,
    ]);
  },
});

Recursive.fromProgram = RecursiveFromProgram;
Recursive.Generic = GenericRecursive;

async function RecursiveFromProgram<
  DataType extends ProvablePure<any>,
  InputType extends ProvablePure<any>,
  Data extends InferNestedProvable<DataType>,
  Input extends InferProvable<InputType>,
  AllInputs extends any[]
>(program: {
  publicInputType: InputType;
  publicOutputType: ProvablePure<Credential<Data>>;
  analyzeMethods(): Promise<{
    [I in keyof any]: any;
  }>;
  maxProofsVerified(): Promise<0 | 1 | 2>;
  compile: (options?: {
    cache?: Cache;
    forceRecompile?: boolean;
    proofsEnabled?: boolean;
  }) => Promise<{ verificationKey: VerificationKey }>;

  run(...inputs: AllInputs): Promise<{
    proof: Proof<Input, Credential<Data>>;
    auxiliaryOutput: undefined;
  }>;
}) {
  const featureFlags = await FeatureFlags.fromZkProgram(program);
  const maxProofsVerified = await program.maxProofsVerified();

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

      async create(...inputs: AllInputs): Promise<Recursive<Data, Input>> {
        let vk = await this.compile();
        let result = await program.run(...inputs);
        let proof = InputProof.fromProof(result.proof);
        return {
          version: 'v0',
          metadata: undefined,
          credential: proof.publicOutput,
          witness: { type: 'recursive', vk, proof },
        };
      },

      async compile(options?: {
        cache?: Cache;
        forceRecompile?: boolean;
        proofsEnabled?: boolean;
      }) {
        if (isCompiled) return vk!;
        let result = await program.compile(options);
        vk = result.verificationKey;
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
