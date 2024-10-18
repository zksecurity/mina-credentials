import { describe, test } from 'node:test';
import assert from 'node:assert';
import { Field, Bytes, PublicKey, Signature } from 'o1js';
import { createProgram } from '../src/program.ts';
import {
  Claim,
  Constant,
  Operation,
  Spec,
  type UserInputs,
} from '../src/program-spec.ts';
import { Credential } from '../src/credential-index.ts';
import { createOwnerSignature, owner } from './test-utils.ts';

const Bytes32 = Bytes(32);
const InputData = { age: Field, name: Bytes32 };

// TODO
let context = Field(0);

// simple spec to create a proof credential that's used recursively
const inputProofSpec = Spec(
  { owner: Claim(PublicKey), data: Claim(InputData) },
  ({ owner, data }) => ({
    data: Operation.record({ owner, data }),
  })
);
const inputProgram = createProgram(inputProofSpec);
let inputVk = await inputProgram.compile();

const ProvedData = await Credential.proofFromProgram(inputProgram);

const spec = Spec(
  {
    provedData: ProvedData,
    targetAge: Claim(Field),
    targetName: Constant(Bytes32, Bytes32.fromString('Alice')),
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
let data = { age: Field(18), name: Bytes32.fromString('Alice') };

await describe('program with proof credential', async () => {
  await test('compile program', async () => {
    await program.compile();
  });

  await test('run program with valid inputs', async () => {
    let provedData = await createProofCredential(data);
    let ownerSignature = createOwnerSignature(context, [
      ProvedData,
      provedData,
    ]);

    const proof = await program.run({
      context,
      ownerSignature,
      credentials: { provedData },
      claims: { targetAge: Field(18) },
    });

    assert(proof, 'Proof should be generated');

    assert.deepStrictEqual(
      proof.publicInput.claims.targetAge,
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
    let provedData = await createInvalidProofCredential(data);
    let ownerSignature = createOwnerSignature(context, [
      ProvedData,
      provedData,
    ]);

    await assert.rejects(
      async () =>
        await program.run({
          context,
          ownerSignature,
          credentials: { provedData },
          claims: { targetAge: Field(18) },
        }),
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

  await test('run program with invalid signature', async () => {
    let provedData = await createProofCredential(data);
    // changing the context makes the signature invalid
    let invalidContext = context.add(1);
    let ownerSignature = createOwnerSignature(invalidContext, [
      ProvedData,
      provedData,
    ]);

    await assert.rejects(
      async () =>
        await program.run({
          context,
          ownerSignature,
          credentials: { provedData },
          claims: { targetAge: Field(18) },
        }),
      (err) => {
        assert(err instanceof Error, 'Should throw an Error');
        assert(
          err.message.includes('Invalid owner signature'),
          'Error message should include unsatisfied constraint'
        );
        return true;
      }
    );
  });
});

// helpers

async function createProofCredential(data: {
  age: Field;
  name: Bytes;
}): Promise<UserInputs<typeof spec.inputs>['credentials']['provedData']> {
  let inputProof = await inputProgram.run({
    context,
    // there is no credential, so no signature verification
    ownerSignature: Signature.empty(),
    claims: { owner, data },
    credentials: {},
  });
  let proof = ProvedData.fromProof(inputProof);
  return {
    credential: inputProof.publicOutput,
    witness: { vk: inputVk, proof },
  };
}

async function createInvalidProofCredential(data: {
  age: Field;
  name: Bytes;
}): Promise<UserInputs<typeof spec.inputs>['credentials']['provedData']> {
  let context = Field(0);
  let proof = await ProvedData.dummyProof(
    { context, claims: { owner, data } },
    { owner, data }
  );
  return {
    credential: proof.publicOutput,
    witness: { vk: inputVk, proof },
  };
}
