import { test } from 'node:test';
import assert from 'node:assert';
import { Field, Bytes, PrivateKey, Signature } from 'o1js';
import { createProgram } from '../src/program.ts';
import { Attestation, Input, Operation, Spec } from '../src/program-config.ts';
import { createAttestation } from './test-utils.ts';

test('createProgram with simple spec', async (t) => {
  const Bytes32 = Bytes(32);
  const InputData = { age: Field, name: Bytes32 };

  const spec = Spec(
    {
      signedData: Attestation.signatureNative(InputData),
      targetAge: Input.public(Field),
      targetName: Input.constant(Bytes32, Bytes32.fromString('Alice')),
    },
    ({ signedData, targetAge, targetName }) => ({
      assert: Operation.and(
        Operation.equals(Operation.property(signedData, 'age'), targetAge),
        Operation.equals(Operation.property(signedData, 'name'), targetName)
      ),
      data: Operation.property(signedData, 'age'),
    })
  );

  const program = createProgram(spec);

  await t.test('compile program', async () => {
    const vk = await program.compile();
    assert(vk, 'Verification key should be generated for zk program');
  });

  await t.test('run program with valid input', async () => {
    let data = { age: Field(18), name: Bytes32.fromString('Alice') };
    let signedData = createAttestation(InputData, data);

    const proof = await program.run({ signedData, targetAge: Field(18) });

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

  await t.test('run program with invalid age input', async () => {
    const data = { age: Field(20), name: Bytes32.fromString('Alice') };
    const signedData = createAttestation(InputData, data);

    await assert.rejects(
      async () => await program.run({ signedData, targetAge: Field(18) }),
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
    const signedData = createAttestation(InputData, data);

    await assert.rejects(
      async () => await program.run({ signedData, targetAge: Field(18) }),
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
