import { Proof, VerificationKey, ZkProgram } from 'o1js';
import {
  Input,
  Node,
  privateInputTypes,
  publicInputTypes,
  publicOutputType,
  recombineDataInputs,
  Spec,
  splitUserInputs,
  verifyCredentials,
  type PublicInputs,
  type UserInputs,
} from './program-spec.ts';
import { NestedProvable } from './nested.ts';
import { type ProvablePureType } from './o1js-missing.ts';

export { createProgram };

type Program<Data, Inputs extends Record<string, Input>> = {
  compile(): Promise<VerificationKey>;

  run(input: UserInputs<Inputs>): Promise<Proof<PublicInputs<Inputs>, Data>>;

  program: ZkProgram<
    {
      publicInput: ProvablePureType<PublicInputs<Inputs>>;
      publicOutput: ProvablePureType<Data>;
    },
    any
  >;
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
          verifyCredentials(spec, publicInput, privateInput);

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
    program: program as any,
  };
}

// helper

type GetSpecData<S extends Spec> = S extends Spec<infer Data, any>
  ? Data
  : never;
