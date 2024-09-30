import { test } from 'node:test';
import assert from 'node:assert';
import { Field, Bytes } from 'o1js';
import { createProgram } from '../src/program.ts';
import { Attestation, Input, Operation, Spec } from '../src/program-config.ts';

test('createProgram with simple spec', async (t) => {
  const Bytes32 = Bytes(32);
  const InputData = { age: Field, name: Bytes32 };

  const spec = Spec(
    {
      signedData: Attestation.signature(InputData),
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

  await t.test('compile porgram', async () => {
    const vk = await program.compile();
    assert(vk, 'Verification key should be generated for zk program');
  });
});
