import { Proof, Field, PublicKey, Bytes } from 'o1js';
import {
  type GetData,
  Attestation,
  Input,
  Operation,
  PublicInputs,
  Spec,
} from './program-config.ts';
import { Tuple } from './types.ts';

export { createProgram };

type Program<Data, Inputs extends Tuple<Input>> = {
  compile(): Promise<{ verificationKey: { data: string; hash: Field } }>;

  run(input: { [K in keyof Inputs]: GetData<Inputs[K]> }): Promise<
    Proof<PublicInputs<Inputs>, Data>
  >;
};

function createProgram<S extends Spec>(
  spec: S
): Program<GetSpecData<S>, S['inputs']> {
  throw Error('Not implemented');
}

// inline test

const isMain = import.meta.filename === process.argv[1];
if (isMain) {
  let { Bytes, Struct } = await import('o1js');

  const Bytes32 = Bytes(32);
  const InputData = Struct({ age: Field, name: Bytes32 });

  const spec = Spec(
    [
      Attestation.signature(InputData),
      Input.public(Field),
      Input.constant(Bytes32, Bytes32.fromString('Alice')),
    ],
    (data, targetAge, targetName) => ({
      assert: Operation.and(
        Operation.equals(Operation.property(data, 'age'), targetAge),
        Operation.equals(Operation.property(data, 'name'), targetName)
      ),
      data: Operation.property(data, 'age'),
    })
  );

  let program = createProgram(spec);

  async function notExecuted() {
    // input types are inferred from spec
    // TODO leverage `From<>` type to pass in inputs directly as numbers / strings etc
    let proof = await program.run([
      { age: Field(42), name: Bytes32.fromString('Alice') },
      Field(18),
      Bytes32.fromString('Alice'),
    ]);

    // proof types are inferred from spec
    proof.publicInput satisfies [issuerPubKey: PublicKey, targetAge: Field];
    proof.publicOutput satisfies Field;
  }
}

// helper

type GetSpecData<S extends Spec> = S extends Spec<infer Data, any>
  ? Data
  : never;
