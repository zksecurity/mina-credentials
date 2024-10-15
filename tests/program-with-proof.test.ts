import { describe, test } from 'node:test';
import assert from 'node:assert';
import { Field, Bytes } from 'o1js';
import { createProgram } from '../src/program.ts';
import {
  Credential,
  Input,
  Operation,
  Spec,
  type UserInputs,
} from '../src/program-config.ts';

const Bytes32 = Bytes(32);
const InputData = { age: Field, name: Bytes32 };

// simple spec to create a proof credential that's used recursively
const inputProofSpec = Spec({ data: Input.private(InputData) }, ({ data }) => ({
  data,
}));
const inputProgram = createProgram(inputProofSpec);
let inputVk = await inputProgram.compile();

const ProvedData = await Credential.proofFromProgram(inputProgram);

const spec = Spec(
  {
    provedData: ProvedData,
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

await describe('program with proof credential', async () => {
  await test('compile program', async () => {
    await program.compile();
  });

  await test('run program with valid inputs', async () => {
    let data = { age: Field(18), name: Bytes32.fromString('Alice') };
    let provedData = await createProofCredential(data);

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
    let provedData = await createInvalidProofCredential(data);

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
});

// helpers

async function createProofCredential(data: {
  age: Field;
  name: Bytes;
}): Promise<UserInputs<typeof spec.inputs>['provedData']> {
  let inputProof = await inputProgram.run({ data });
  let proof = ProvedData.fromProof(inputProof);
  return {
    public: inputVk.hash,
    private: { vk: inputVk, proof },
    data: inputProof.publicOutput,
  };
}

async function createInvalidProofCredential(data: {
  age: Field;
  name: Bytes;
}): Promise<UserInputs<typeof spec.inputs>['provedData']> {
  let proof = await ProvedData.dummyProof({}, data);
  return {
    public: inputVk.hash,
    private: { vk: inputVk, proof },
    data,
  };
}
