import { describe, test } from 'node:test';
import assert from 'node:assert';
import { Field, Bytes, PublicKey, Signature } from 'o1js';
import { createProgram } from '../src/program.ts';
import { Claim, Constant, Operation, Spec } from '../src/program-spec.ts';
import { Credential } from '../src/credential-index.ts';
import { createOwnerSignature, owner, ownerKey } from './test-utils.ts';
import { Presentation, PresentationRequest } from '../src/presentation.ts';

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
const Recursive = await Credential.Recursive.fromProgram(
  createProgram(inputProofSpec)
);
let data = { age: Field(18), name: Bytes32.fromString('Alice') };
let provedData = await Recursive.create({
  claims: { owner, data },
  credentials: {},
  context: Field(0), // dummy context
  ownerSignature: Signature.empty(), // no credential => no signature verification
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
let requestInitial = PresentationRequest.noContext(spec, {
  targetAge: Field(18),
});
let request = await Presentation.compile(requestInitial);

await describe('program with proof credential', async () => {
  await test('compile program', async () => {
    await request.program.compile();
  });

  await test('run program with valid inputs', async () => {
    let { proof } = await Presentation.create(ownerKey, {
      request,
      credentials: [provedData],
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

    await assert.rejects(
      async () =>
        await Presentation.create(ownerKey, {
          request,
          credentials: [provedData],
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
        await request.program.run({
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
