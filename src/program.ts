import {
  Proof,
  Field,
  PublicKey,
  PrivateKey,
  Signature,
  VerificationKey,
  Struct,
  ZkProgram,
} from 'o1js';
import {
  Attestation,
  Input,
  Operation,
  privateInputTypes,
  publicInputTypes,
  publicOutputType,
  Spec,
  type PublicInputs,
  type UserInputs,
} from './program-config.ts';
import { ProvableType } from './o1js-missing.ts';

export { createProgram };

type Program<Data, Inputs extends Record<string, Input>> = {
  compile(): Promise<VerificationKey>;

  run(input: UserInputs<Inputs>): Promise<Proof<PublicInputs<Inputs>, Data>>;
};

function createProgram<S extends Spec>(
  spec: S
): Program<GetSpecData<S>, S['inputs']> {
  // 1. split spec inputs into public and private inputs
  let PublicInput = Struct(publicInputTypes(spec));
  let PublicOutput = publicOutputType(spec);
  let PrivateInput = Struct(privateInputTypes(spec));

  let program = ZkProgram({
    name: 'todo',
    publicInput: PublicInput,
    publicOutput: PublicOutput,
    methods: {
      run: {
        privateInputs: [PrivateInput],
        method(publicInput, privateInput) {
          throw Error('Not implemented');
        },
      },
    },
  });

  return {
    async compile() {
      const result = await program.compile();
      return result.verificationKey;
    },
    run(input) {
      throw Error('Not implemented');
    },
  };
}

// inline test

const isMain = import.meta.filename === process.argv[1];
if (isMain) {
  let { Bytes, Struct } = await import('o1js');

  const Bytes32 = Bytes(32);
  class InputData extends Struct({ age: Field, name: Bytes32 }) {}

  // TODO always include owner pk and verify signature on it
  const spec = Spec(
    {
      signedData: Attestation.signature(InputData),
      targetAge: Input.public(Field),
      targetName: Input.constant(Bytes32, Bytes32.fromString('Alice')),
    },
    ({ signedData, targetAge, targetName }) => ({
      assert: Operation.and(
        Operation.equals(Operation.property(signedData, 'age'), targetAge),
        Operation.equals(Operation.property(signedData, 'name'), targetName)
      ),
      data: Operation.property(signedData, 'age'),
    })
  );

  function createAttestation<Data>(type: ProvableType<Data>, data: Data) {
    let issuer = PrivateKey.randomKeypair();
    let signature = Signature.create(
      issuer.privateKey,
      ProvableType.get(type).toFields(data)
    );
    return { public: issuer.publicKey, private: signature, data };
  }

  let data = { age: Field(42), name: Bytes32.fromString('Alice') };
  let signedData = createAttestation(InputData, data);

  let program = createProgram(spec);

  async function notExecuted() {
    await program.compile();

    // input types are inferred from spec
    // TODO leverage `From<>` type to pass in inputs directly as numbers / strings etc
    let proof = await program.run({ signedData, targetAge: Field(18) });

    // proof types are inferred from spec
    proof.publicInput satisfies { signedData: PublicKey; targetAge: Field };
    proof.publicOutput satisfies Field;
  }
}

// helper

type GetSpecData<S extends Spec> = S extends Spec<infer Data, any>
  ? Data
  : never;
