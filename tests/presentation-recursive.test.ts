import { describe, test } from 'node:test';
import assert from 'node:assert';
import { Field, Bytes } from 'o1js';
import { createProgram } from '../src/program.ts';
import { Claim, Constant, Spec } from '../src/program-spec.ts';
import { Credential } from '../src/credential-index.ts';
import { owner, ownerKey } from './test-utils.ts';
import { Presentation, PresentationRequest } from '../src/presentation.ts';
import { signCredentials } from '../src/credential.ts';
import { Operation } from '../src/operation.ts';

const Bytes32 = Bytes(32);
const InputData = { age: Field, name: Bytes32 };

// create imported credential
// TODO create a more interesting input proof
const Imported = await Credential.Imported.fromMethod(
  { name: 'dummy', privateInput: InputData, data: InputData },
  async ({ privateInput: data }) => data
);

let data = { age: Field(18), name: Bytes32.fromString('Alice') };
let provedData = await Imported.create({
  owner,
  privateInput: data,
  publicInput: undefined,
});
let credentialJson = Credential.toJSON(provedData);
let storedCredential = await Credential.fromJSON(credentialJson);
await Credential.validate(storedCredential);

// define presentation spec
const spec = Spec(
  {
    provedData: Imported.spec,
    targetAge: Claim(Field),
    targetName: Constant(Bytes32, Bytes32.fromString('Alice')),
  },
  ({ provedData, targetAge, targetName }) => ({
    assert: Operation.and(
      Operation.equals(Operation.property(provedData, 'age'), targetAge),
      Operation.equals(Operation.property(provedData, 'name'), targetName)
    ),
    outputClaim: Operation.property(provedData, 'age'),
  })
);
let requestInitial = PresentationRequest.noContext(spec, {
  targetAge: Field(18),
});
let json = PresentationRequest.toJSON(requestInitial);

// wallet: deserialize and compile request
let deserialized = PresentationRequest.fromJSON<typeof requestInitial>(
  'no-context',
  json
);
let request = await Presentation.compile(deserialized);

await describe('program with proof credential', async () => {
  await test('program is deserialized correctly', async () => {
    let program1 = createProgram(requestInitial.spec);
    let analyze1 = await program1.program.analyzeMethods();
    let program2 = createProgram(deserialized.spec);
    let analyze2 = await program2.program.analyzeMethods();

    assert.deepStrictEqual(
      analyze1.run?.digest,
      analyze2.run?.digest,
      'Same circuit digest'
    );
  });

  await test('compile program', async () => {
    await request.program.compile();
  });

  await test('run program with valid inputs', async () => {
    let presentation = await Presentation.create(ownerKey, {
      request,
      credentials: [storedCredential],
      context: undefined,
    });
    let outputClaim = await Presentation.verify(
      request,
      presentation,
      undefined
    );

    let { claims } = presentation;
    assert.deepStrictEqual(
      claims.targetAge,
      Field(18),
      'Public input should match'
    );
    assert.deepStrictEqual(
      outputClaim,
      Field(18),
      'Output claim should match the age'
    );
  });

  await test('run program with invalid proof', async () => {
    let provedData = await Imported.dummy({ owner, data });

    await assert.rejects(
      () =>
        Presentation.create(ownerKey, {
          request,
          credentials: [provedData],
          context: undefined,
        }),
      /Constraint unsatisfied/,
      'Program should fail with invalid input'
    );
  });

  await test('run program with invalid signature', async () => {
    // changing the context makes the signature invalid
    let actualContext = Field(0);
    let invalidContext = Field(1);
    let ownerSignature = signCredentials(ownerKey, actualContext, {
      ...provedData,
      credentialType: Imported.spec,
    });

    await assert.rejects(
      () =>
        request.program.run({
          context: invalidContext,
          ownerSignature,
          credentials: { provedData },
          claims: { targetAge: Field(18) },
        }),
      /Invalid owner signature/
    );
  });
});
