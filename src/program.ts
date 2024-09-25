import {
  Proof,
  Field,
  PublicKey,
  PrivateKey,
  Signature,
  VerificationKey,
  Provable,
} from 'o1js';
import {
  Attestation,
  Input,
  Operation,
  Spec,
  type PublicInputs,
  type UserInputs,
} from './program-config.ts';
import type { Tuple } from './types.ts';

export { createProgram };

type Program<Data, Inputs extends Tuple<Input>> = {
  compile(): Promise<VerificationKey>;

  run(...input: UserInputs<Inputs>): Promise<Proof<PublicInputs<Inputs>, Data>>;
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
  class InputData extends Struct({ age: Field, name: Bytes32 }) {}

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

  function createAttestation<Data>(type: Provable<Data>, data: Data) {
    let issuer = PrivateKey.randomKeypair();
    let signature = Signature.create(issuer.privateKey, type.toFields(data));
    return { public: issuer.publicKey, private: signature, data };
  }

  let data = { age: Field(42), name: Bytes32.fromString('Alice') };
  let signedData = createAttestation(InputData, data);

  async function notExecuted() {
    let program = createProgram(spec);

    // input types are inferred from spec
    // TODO leverage `From<>` type to pass in inputs directly as numbers / strings etc
    let proof = await program.run(signedData, Field(18));

    // proof types are inferred from spec
    proof.publicInput satisfies [issuerPubKey: PublicKey, targetAge: Field];
    proof.publicOutput satisfies Field;
  }
}

// helper

type GetSpecData<S extends Spec> = S extends Spec<infer Data, any>
  ? Data
  : never;
