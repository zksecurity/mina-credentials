import {
  Proof,
  Field,
  PublicKey,
  PrivateKey,
  Signature,
  VerificationKey,
  ZkProgram,
  Provable,
} from 'o1js';
import {
  Attestation,
  Input,
  Node,
  Operation,
  privateInputTypes,
  publicInputTypes,
  publicOutputType,
  recombineDataInputs,
  Spec,
  splitUserInputs,
  verifyAttestations,
  type PublicInputs,
  type UserInputs,
} from './program-config.ts';
import { NestedProvable, type NestedProvableFor } from './nested.ts';

export { createProgram };

type Program<Data, Inputs extends Record<string, Input>> = {
  compile(): Promise<VerificationKey>;

  run(input: UserInputs<Inputs>): Promise<Proof<PublicInputs<Inputs>, Data>>;
};

function createProgram<S extends Spec>(
  spec: S
): Program<GetSpecData<S>, S['inputs']> {
  // 1. split spec inputs into public and private inputs
  let PublicInput = NestedProvable.get(publicInputTypes(spec));
  let PublicOutput = publicOutputType(spec);
  let PrivateInput = NestedProvable.get(privateInputTypes(spec));

  let program = ZkProgram({
    name: `todo`, // we should create a name deterministically derived from the spec, e.g. `credential-${hash(spec)}`
    publicInput: PublicInput,
    publicOutput: PublicOutput,
    methods: {
      run: {
        privateInputs: [PrivateInput],
        method(publicInput, privateInput) {
          verifyAttestations(spec, publicInput, privateInput);

          let root = recombineDataInputs(spec, publicInput, privateInput);
          let assertion = Node.eval(root, spec.logic.assert);
          let output = Node.eval(root, spec.logic.data);
          assertion.assertTrue('Program assertion failed!');
          return output;
        },
      },
    },
  });

  return {
    async compile() {
      const result = await program.compile();
      return result.verificationKey;
    },
    async run(input) {
      let { publicInput, privateInput } = splitUserInputs(spec, input);
      let result = await program.run(publicInput, privateInput);
      return result as any;
    },
  };
}

// helper

type GetSpecData<S extends Spec> = S extends Spec<infer Data, any>
  ? Data
  : never;
