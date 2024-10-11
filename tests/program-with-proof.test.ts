import { test } from 'node:test';
import assert from 'node:assert';
import { Field, Bytes, DynamicProof, Struct } from 'o1js';
import { createProgram } from '../src/program.ts';
import {
  Attestation,
  Input,
  Operation,
  Spec,
  type UserInputs,
} from '../src/program-config.ts';

const Bytes32 = Bytes(32);
const InputData = { age: Field, name: Bytes32 };

// simple spec to create a proof attestation that's used recursively
const inputProofSpec = Spec({ data: Input.private(InputData) }, ({ data }) => ({
  data,
}));
const inputProgram = createProgram(inputProofSpec);

// TODO simplify this
class InputProof extends DynamicProof<{}, { age: Field; name: Bytes }> {
  static publicInputType = Struct({});
  static publicOutputType = Struct({ age: Field, name: Bytes32 });
  static maxProofsVerified: 0 = 0;
}
let inputVk = await inputProgram.compile();

const spec = Spec(
  {
    provedData: Attestation.proof(InputProof, InputData),
    targetAge: Input.public(Field),
    targetName: Input.constant(Bytes32, Bytes32.fromString('Alice')),
  },
  ({ provedData, targetAge, targetName }) => ({
    assert: Operation.and(
      Operation.equals(Operation.property(provedData, 'age'), targetAge),
      Operation.equals(Operation.property(provedData, 'name'), targetName)
    ),
    data: Operation.property(provedData, 'age'),
  })
);

const program = createProgram(spec);

await test('compile program', async () => {
  await program.compile();
});

await test('run program with valid input', async () => {
  let data = { age: Field(18), name: Bytes32.fromString('Alice') };
  let provedData = await createProofAttestation(data);

  const proof = await program.run({ provedData, targetAge: Field(18) });

  assert(proof, 'Proof should be generated');

  assert.deepStrictEqual(
    proof.publicInput.targetAge,
    Field(18),
    'Public input should match'
  );
  assert.deepStrictEqual(
    proof.publicOutput,
    Field(18),
    'Public output should match the age'
  );
});

await test('run program with invalid proof', async () => {
  const data = { age: Field(18), name: Bytes32.fromString('Alice') };
  let provedData = await createInvalidProofAttestation(data);

  await assert.rejects(
    async () => await program.run({ provedData, targetAge: Field(18) }),
    (err) => {
      assert(err instanceof Error, 'Should throw an Error');
      assert(
        err.message.includes('Constraint unsatisfied'),
        'Error message should include unsatisfied constraint'
      );
      return true;
    },
    'Program should fail with invalid input'
  );
});

// helpers

async function createProofAttestation(data: {
  age: Field;
  name: Bytes;
}): Promise<UserInputs<typeof spec.inputs>['provedData']> {
  let inputProof = await inputProgram.run({ data });
  let proof = InputProof.fromProof(inputProof);
  return {
    public: inputVk.hash,
    private: { vk: inputVk, proof },
    data: inputProof.publicOutput,
  };
}

async function createInvalidProofAttestation(data: {
  age: Field;
  name: Bytes;
}): Promise<UserInputs<typeof spec.inputs>['provedData']> {
  let proof = await InputProof.dummy({}, data, 0);
  return {
    public: inputVk.hash,
    private: { vk: inputVk, proof },
    data,
  };
}
