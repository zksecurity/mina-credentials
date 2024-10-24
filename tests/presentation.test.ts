import { test } from 'node:test';
import assert from 'node:assert';
import { Field, Bytes } from 'o1js';
import { Claim, Constant, Operation, Spec } from '../src/program-spec.ts';
import { issuerKey, owner, ownerKey } from './test-utils.ts';
import { Credential } from '../src/credential-index.ts';
import { Presentation, PresentationRequest } from '../src/presentation.ts';

test('program with simple spec and signature credential', async (t) => {
  const Bytes32 = Bytes(32);

  const spec = Spec(
    {
      signedData: Credential.Simple({ age: Field, name: Bytes32 }),
      targetAge: Claim(Field),
      targetName: Constant(Bytes32, Bytes32.fromString('Alice')),
    },
    ({ signedData, targetAge, targetName }) => ({
      assert: Operation.and(
        Operation.equals(Operation.property(signedData, 'age'), targetAge),
        Operation.equals(Operation.property(signedData, 'name'), targetName)
      ),
      data: Operation.property(signedData, 'age'),
    })
  );

  // presentation request
  // TODO proper context
  let requestInitial = PresentationRequest.noContext(spec, {
    targetAge: Field(18),
  });
  let json = PresentationRequest.toJSON(requestInitial);

  // wallet: deserialize and compile request
  let deserialized = PresentationRequest.fromJSON<typeof requestInitial>(json);
  let request = await Presentation.compile(deserialized);

  await t.test('compile program', async () => {
    assert(
      await request.program.compile(),
      'Verification key should be generated for zk program'
    );
  });

  await t.test('run program with valid input', async () => {
    // issuance
    let data = { age: Field(18), name: Bytes32.fromString('Alice') };
    let signedData = Credential.sign(issuerKey, { owner, data });

    // presentation
    let { proof } = await Presentation.create(ownerKey, {
      request,
      credentials: [signedData],
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

  await t.test('run program with invalid age input', async () => {
    const data = { age: Field(20), name: Bytes32.fromString('Alice') };
    let signedData = Credential.sign(issuerKey, { owner, data });

    await assert.rejects(
      async () =>
        await Presentation.create(ownerKey, {
          request,
          credentials: [signedData],
        }),
      (err) => {
        assert(err instanceof Error, 'Should throw an Error');
        assert(
          err.message.includes('Program assertion failed'),
          'Error message should include program assertion failure'
        );
        assert(
          err.message.includes('Constraint unsatisfied'),
          'Error message should include unsatisfied constraint'
        );
        return true;
      },
      'Program should fail with invalid input'
    );
  });

  await t.test('run program with invalid name input', async () => {
    const data = { age: Field(18), name: Bytes32.fromString('Bob') };
    let signedData = Credential.sign(issuerKey, { owner, data });

    await assert.rejects(
      async () =>
        await Presentation.create(ownerKey, {
          request,
          credentials: [signedData],
        }),
      (err) => {
        assert(err instanceof Error, 'Should throw an Error');
        assert(
          err.message.includes('Program assertion failed'),
          'Error message should include program assertion failure'
        );
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

test('program with owner and issuer operations', async (t) => {
  const InputData = { dummy: Field };
  const SignedData = Credential.Simple(InputData);

  const spec = Spec(
    {
      signedData: SignedData,
      expectedDummy: Constant(Field, Field(123)),
    },
    ({ signedData, expectedDummy }) => ({
      assert: Operation.equals(
        Operation.property(signedData, 'dummy'),
        expectedDummy
      ),
      data: Operation.record({
        owner: Operation.owner,
        issuer: Operation.issuer(signedData),
        dummy: Operation.property(signedData, 'dummy'),
      }),
    })
  );
  let requestInitial = PresentationRequest.noContext(spec, {});
  let request = await Presentation.compile(requestInitial);

  await t.test('compile program', async () => {
    assert(await request.program.compile(), 'Program should compile');
  });

  await t.test('run program with valid input', async () => {
    let dummyData = { dummy: Field(123) };
    let signedData = Credential.sign(issuerKey, { owner, data: dummyData });
    let { proof } = await Presentation.create(ownerKey, {
      request,
      credentials: [signedData],
    });

    assert(proof, 'Proof should be generated');

    assert.deepStrictEqual(proof.publicOutput.owner, owner);

    const expectedIssuerField = SignedData.issuer(signedData.witness);
    assert.deepStrictEqual(proof.publicOutput.issuer, expectedIssuerField);

    assert.deepStrictEqual(proof.publicOutput.dummy, Field(123));
  });
});
