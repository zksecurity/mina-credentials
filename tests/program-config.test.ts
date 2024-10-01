import { test } from 'node:test';
import assert from 'node:assert';
import { Bytes, Field } from 'o1js';
import {
  Spec,
  Input,
  Operation,
  Node,
  Attestation,
  type UserInputs,
  splitUserInputs,
  recombineDataInputs,
} from '../src/program-config.ts';
import { createAttestation } from './test-utils.ts';

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

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
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

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(30));
  });

  await t.test('Spec with nested properties', () => {
    const InputData = { age: Field, name: Bytes32 };
    const NestedInputData = { person: InputData, points: Field };

    const spec = Spec(
      {
        data: Input.private(NestedInputData),
        targetAge: Input.public(Field),
        targetPoints: Input.public(Field),
      },
      ({ data, targetAge, targetPoints }) => ({
        assert: Operation.and(
          Operation.equals(
            Operation.property(Operation.property(data, 'person'), 'age'),
            targetAge
          ),
          Operation.equals(Operation.property(data, 'points'), targetPoints)
        ),
        data: Operation.property(Operation.property(data, 'person'), 'name'),
      })
    );

    const root = {
      data: {
        person: { age: Field(25), name: Bytes32.fromString('Bob') },
        points: Field(100),
      },
      targetAge: Field(25),
      targetPoints: Field(100),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Bytes32.fromString('Bob'));
  });

  await t.test('Spec with constant input', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Input.private(InputData),
        constAge: Input.constant(Field, Field(25)),
      },
      ({ data, constAge }) => ({
        assert: Operation.equals(Operation.property(data, 'age'), constAge),
        data: Operation.property(data, 'name'),
      })
    );

    const root = {
      data: { age: Field(25), name: Bytes32.fromString('Charlie') },
      constAge: Field(25),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Bytes32.fromString('Charlie'));
  });

  await t.test('Spec with attestation', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        signedData: Attestation.signature(InputData),
        targetAge: Input.public(Field),
        targetName: Input.public(Bytes32),
      },
      ({ signedData, targetAge, targetName }) => ({
        assert: Operation.and(
          Operation.equals(Operation.property(signedData, 'age'), targetAge),
          Operation.equals(Operation.property(signedData, 'name'), targetName)
        ),
        data: Operation.property(signedData, 'age'),
      })
    );

    const data = { age: Field(30), name: Bytes32.fromString('David') };
    const signedData = createAttestation(InputData, data);

    let userInputs: UserInputs<typeof spec.inputs> = {
      signedData,
      targetAge: Field(30),
      targetName: Bytes32.fromString('David'),
    };

    let { privateInput, publicInput } = splitUserInputs(spec, userInputs);
    let root = recombineDataInputs(spec, publicInput, privateInput);

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(30));
  });
});
