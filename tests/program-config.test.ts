import { test } from 'node:test';
import assert from 'node:assert';
import { Bytes, Field } from 'o1js';
import { Spec, Input, Operation, Node } from '../src/program-config.ts';

test(' Spec and Node operations', async (t) => {
  const Bytes32 = Bytes(32);

  await t.test('Basic Spec with equality check', () => {
    const InputData = { age: Field };
    const spec = Spec(
      {
        data: Input.private(InputData),
        targetAge: Input.public(Field),
      },
      ({ data, targetAge }) => ({
        assert: Operation.equals(Operation.property(data, 'age'), targetAge),
        data: Operation.property(data, 'age'),
      })
    );

    const root = {
      data: { age: Field(25) },
      targetAge: Field(25),
    };

    console.log('spec.logic.assert:', spec.logic.assert);
    console.log('spec.logic.data:', spec.logic.data);

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toString(), 'true');
    assert.deepStrictEqual(dataResult, Field(25));
  });

  await t.test('Spec with multiple assertions', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Input.private(InputData),
        targetAge: Input.public(Field),
        targetName: Input.public(Bytes32),
      },
      ({ data, targetAge, targetName }) => ({
        assert: Operation.and(
          Operation.equals(Operation.property(data, 'age'), targetAge),
          Operation.equals(Operation.property(data, 'name'), targetName)
        ),
        data: Operation.property(data, 'age'),
      })
    );

    const root = {
      data: { age: Field(30), name: Bytes32.fromString('Alice') },
      targetAge: Field(30),
      targetName: Bytes32.fromString('Alice'),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toString(), 'true');
    assert.deepStrictEqual(dataResult, Field(30));
  });
});
