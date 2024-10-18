import { describe, test } from 'node:test';
import assert from 'node:assert';
import { Field, Bytes, PublicKey, Signature } from 'o1js';
import { createProgram } from '../src/program.ts';
import { Claim, Constant, Operation, Spec } from '../src/program-spec.ts';
import { Credential } from '../src/credential-index.ts';
import { createOwnerSignature, owner } from './test-utils.ts';

const Bytes32 = Bytes(32);
const InputData = { age: Field, name: Bytes32 };

// TODO
let context = Field(0);

// simple spec to create a proof credential that's used recursively
// TODO create a more interesting input proof
const inputProofSpec = Spec(
  { owner: Claim(PublicKey), data: Claim(InputData) },
  ({ owner, data }) => ({
    data: Operation.record({ owner, data }),
  })
);

// create recursive credential
const Recursive = await Credential.RecursiveFromProgram(
  createProgram(inputProofSpec)
);
let data = { age: Field(18), name: Bytes32.fromString('Alice') };
let provedData = await Recursive.create({
  claims: { owner, data },
  credentials: {},
  // dummy context
  context: Field(0),
  // there is no credential, so no signature verification
  ownerSignature: Signature.empty(),
});

// define presentation spec
const spec = Spec(
  {
    provedData: Recursive,
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

await describe('program with proof credential', async () => {
  await test('compile program', async () => {
    await program.compile();
  });

  await test('run program with valid inputs', async () => {
    let ownerSignature = createOwnerSignature(context, [Recursive, provedData]);

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
    let provedData = await Recursive.dummy({ owner, data });
    let ownerSignature = createOwnerSignature(context, [Recursive, provedData]);

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
    // changing the context makes the signature invalid
    let invalidContext = context.add(1);
    let ownerSignature = createOwnerSignature(invalidContext, [
      Recursive,
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
