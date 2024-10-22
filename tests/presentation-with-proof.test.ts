import { describe, test } from 'node:test';
import assert from 'node:assert';
import { Field, Bytes, PublicKey, Signature } from 'o1js';
import { createProgram } from '../src/program.ts';
import { Claim, Constant, Operation, Spec } from '../src/program-spec.ts';
import { Credential } from '../src/credential-index.ts';
import { owner, ownerKey } from './test-utils.ts';
import { Presentation, PresentationRequest } from '../src/presentation.ts';
import { signCredentials } from '../src/credential.ts';

const Bytes32 = Bytes(32);
const InputData = { age: Field, name: Bytes32 };

// TODO
let context = Field(0);

// simple spec to create a proof credential that's used recursively
// TODO create a more interesting input proof
const inputProofSpec = Spec(
  { inputOwner: Claim(PublicKey), data: Claim(InputData) },
  ({ inputOwner, data }) => ({
    data: Operation.record({ owner: inputOwner, data }),
  })
);

// create recursive credential
const Recursive = await Credential.Recursive.fromProgram(
  createProgram(inputProofSpec)
);
let data = { age: Field(18), name: Bytes32.fromString('Alice') };
let provedData = await Recursive.create({
  claims: { inputOwner: owner, data },
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
let json = PresentationRequest.toJSON(requestInitial);

// wallet: deserialize and compile request
// TODO: Information about Recursive program is lost here, this seems to create some problem
let deserialized = PresentationRequest.fromJSON<typeof requestInitial>(json);

console.log('Original:', requestInitial.spec.inputs.provedData.witness);
console.log('Deserialized:', deserialized.spec.inputs.provedData.witness);

let analyze1 = await createProgram(
  requestInitial.spec
).program.analyzeMethods();
let analyze2 = await createProgram(deserialized.spec).program.analyzeMethods();
console.log('Original:', analyze1);
console.log('Deserialized:', analyze2);

assert.deepStrictEqual(
  deserialized.spec.inputs.provedData.data,
  requestInitial.spec.inputs.provedData.data
);
assert.deepStrictEqual(
  deserialized.spec.inputs.provedData.witness,
  requestInitial.spec.inputs.provedData.witness
);
assert.deepStrictEqual(deserialized.spec.logic, requestInitial.spec.logic);

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
    let ownerSignature = signCredentials(ownerKey, invalidContext, {
      ...provedData,
      credentialType: Recursive,
    });

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
