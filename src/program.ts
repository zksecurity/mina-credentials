import { Field, Proof, Signature, VerificationKey, ZkProgram } from 'o1js';
import {
  type Input,
  Node,
  privateInputTypes,
  publicInputTypes,
  publicOutputType,
  recombineDataInputs,
  Spec,
  splitUserInputs,
  extractCredentialInputs,
  type PublicInputs,
  type UserInputs,
} from './program-spec.ts';
import { NestedProvable } from './nested.ts';
import { type ProvablePureType } from './o1js-missing.ts';
import { verifyCredentials } from './credential.ts';

export { createProgram, type Program };

type Program<Output, Inputs extends Record<string, Input>> = {
  compile(): Promise<VerificationKey>;

  run(input: UserInputs<Inputs>): Promise<Proof<PublicInputs<Inputs>, Output>>;

  program: ZkProgram<
    {
      publicInput: ProvablePureType<PublicInputs<Inputs>>;
      publicOutput: ProvablePureType<Output>;
      methods: any;
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
        async method(
          publicInput: { context: Field; claims: Record<string, any> },
          privateInput: {
            ownerSignature: Signature;
            credentials: Record<string, any>;
          }
        ) {
          let credentials = extractCredentialInputs(
            spec,
            publicInput,
            privateInput
          );
          // TODO return issuers from this function and pass it to app logic
          let credentialOutputs = verifyCredentials(credentials);

          let root = recombineDataInputs(
            spec,
            publicInput,
            privateInput,
            credentialOutputs
          );
          let assertion = Node.eval(root, spec.logic.assert);
          let output = Node.eval(root, spec.logic.data);
          assertion.assertTrue('Program assertion failed!');
          return { publicOutput: output };
        },
      },
    },
  });

  let isCompiled = false;
  let verificationKey: VerificationKey | undefined;

  return {
    async compile() {
      if (isCompiled) return verificationKey!;
      let result = await program.compile();
      isCompiled = true;
      verificationKey = result.verificationKey;
      return verificationKey;
    },
    async run(input) {
      let { publicInput, privateInput } = splitUserInputs(input);
      let result = await program.run(publicInput, privateInput);
      return result.proof as any;
    },
    program: program as any,
  };
}

// helper

type GetSpecData<S extends Spec> = S extends Spec<infer Data, any>
  ? Data
  : never;
