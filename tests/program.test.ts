import { test } from 'node:test';
import assert from 'node:assert';
import { Field, Bytes, PrivateKey, Signature } from 'o1js';
import { createProgram } from '../src/program.ts';
import { Attestation, Input, Operation, Spec } from '../src/program-config.ts';
import { NestedProvable } from '../src/nested.ts';

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
});

function createAttestation<Data>(type: NestedProvable, data: Data) {
  const issuer = PrivateKey.random();
  const signature = Signature.create(
    issuer,
    NestedProvable.get(type).toFields(data)
  );
  return { public: issuer.toPublicKey(), private: signature, data };
}
