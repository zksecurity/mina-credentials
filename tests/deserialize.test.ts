import { test } from 'node:test';
import assert from 'node:assert';
import {
  Field,
  Bool,
  UInt8,
  UInt32,
  UInt64,
  PublicKey,
  Signature,
  PrivateKey,
} from 'o1js';
import {
  Spec,
  Input,
  Node,
  Attestation,
  Operation,
} from '../src/program-config.ts';
import {
  serializeProvableType,
  serializeProvable,
  serializeNestedProvableFor,
  convertNodeToSerializable,
  convertInputToSerializable,
  convertSpecToSerializable,
  serializeSpec,
} from '../src/serialize-spec.ts';
import {
  deserializeSpec,
  deserializeInputs,
  deserializeInput,
  deserializeNode,
  deserializeProvableType,
  deserializeProvable,
  deserializeNestedProvableFor,
} from '../src/deserialize-spec.ts';

import { createAttestation } from './test-utils.ts';

test('Deserialize Spec', async (t) => {
  await t.test('deserializeProvable', async (t) => {
    await t.test('Field', () => {
      const deserialized = deserializeProvable('Field', '42');
      assert(deserialized instanceof Field, 'Should be instance of Field');
      assert.strictEqual(
        deserialized.toString(),
        '42',
        'Should have correct value'
      );
    });

    await t.test('Bool', () => {
      const deserializedTrue = deserializeProvable('Bool', 'true');
      assert(deserializedTrue instanceof Bool, 'Should be instance of Bool');
      assert.strictEqual(deserializedTrue.toBoolean(), true, 'Should be true');

      const deserializedFalse = deserializeProvable('Bool', 'false');
      assert(deserializedFalse instanceof Bool, 'Should be instance of Bool');
      assert.strictEqual(
        deserializedFalse.toBoolean(),
        false,
        'Should be false'
      );
    });

    await t.test('UInt8', () => {
      const deserialized = deserializeProvable('UInt8', '255');
      assert(deserialized instanceof UInt8, 'Should be instance of UInt8');
      assert.strictEqual(
        deserialized.toString(),
        '255',
        'Should have correct value'
      );
    });

    await t.test('UInt32', () => {
      const deserialized = deserializeProvable('UInt32', '4294967295');
      assert(deserialized instanceof UInt32, 'Should be instance of UInt32');
      assert.strictEqual(
        deserialized.toString(),
        '4294967295',
        'Should have correct value'
      );
    });

    await t.test('UInt64', () => {
      const deserialized = deserializeProvable(
        'UInt64',
        '18446744073709551615'
      );
      assert(deserialized instanceof UInt64, 'Should be instance of UInt64');
      assert.strictEqual(
        deserialized.toString(),
        '18446744073709551615',
        'Should have correct value'
      );
    });

    await t.test('PublicKey', () => {
      const publicKeyBase58 =
        'B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg';
      const deserialized = deserializeProvable('PublicKey', publicKeyBase58);
      assert(
        deserialized instanceof PublicKey,
        'Should be instance of PublicKey'
      );
      assert.strictEqual(
        deserialized.toBase58(),
        publicKeyBase58,
        'Should have correct value'
      );
    });

    await t.test('Signature', () => {
      // Create a valid signature
      const privateKey = PrivateKey.random();
      const publicKey = privateKey.toPublicKey();
      const message = [Field(1), Field(2), Field(3)];
      const signature = Signature.create(privateKey, message);

      // Serialize the signature using serializeProvable
      const serializedSignature = serializeProvable(signature);

      // Deserialize the signature
      const deserialized = deserializeProvable(
        serializedSignature.type,
        serializedSignature.value
      );

      assert(
        deserialized instanceof Signature,
        'Should be instance of Signature'
      );
      assert(
        deserialized.verify(publicKey, message).toBoolean(),
        'Deserialized signature should be valid'
      );

      // Additional check to ensure serialized and deserialized signatures match
      const reserializedSignature = serializeProvable(deserialized);
      assert.deepStrictEqual(
        serializedSignature,
        reserializedSignature,
        'Serialized and reserialized signatures should match'
      );
    });

    await t.test('Invalid type', () => {
      assert.throws(
        () => deserializeProvable('InvalidType' as any, '42'),
        { message: 'Unsupported provable type: InvalidType' },
        'Should throw for invalid type'
      );
    });
  });
});

test('deserializeProvableType', async (t) => {
  await t.test('should deserialize Field type', () => {
    const result = deserializeProvableType({ type: 'Field' });
    assert.strictEqual(result, Field);
  });

  await t.test('should deserialize Bool type', () => {
    const result = deserializeProvableType({ type: 'Bool' });
    assert.strictEqual(result, Bool);
  });

  await t.test('should deserialize UInt8 type', () => {
    const result = deserializeProvableType({ type: 'UInt8' });
    assert.strictEqual(result, UInt8);
  });

  await t.test('should deserialize UInt32 type', () => {
    const result = deserializeProvableType({ type: 'UInt32' });
    assert.strictEqual(result, UInt32);
  });

  await t.test('should deserialize UInt64 type', () => {
    const result = deserializeProvableType({ type: 'UInt64' });
    assert.strictEqual(result, UInt64);
  });

  await t.test('should deserialize PublicKey type', () => {
    const result = deserializeProvableType({ type: 'PublicKey' });
    assert.strictEqual(result, PublicKey);
  });

  await t.test('should deserialize Signature type', () => {
    const result = deserializeProvableType({ type: 'Signature' });
    assert.strictEqual(result, Signature);
  });

  await t.test('should throw error for unsupported type', async (t) => {
    try {
      deserializeProvableType({ type: 'UnsupportedType' });
      assert.fail('Expected an error to be thrown');
    } catch (error) {
      assert(error instanceof Error);
      assert.strictEqual(
        error.message,
        'Unsupported provable type: UnsupportedType'
      );
    }
  });
});

test('deserializeInput', async (t) => {
  await t.test('should deserialize constant input', () => {
    const input = Input.constant(Field, Field(42));
    const serialized = convertInputToSerializable(input);
    const deserialized = deserializeInput(serialized);

    assert.deepStrictEqual(deserialized, input);
  });

  await t.test('should deserialize public input', () => {
    const input = Input.public(Field);
    const serialized = convertInputToSerializable(input);
    const deserialized = deserializeInput(serialized);

    assert.deepStrictEqual(deserialized, input);
  });

  await t.test('should deserialize private input', () => {
    const input = Input.private(Signature);
    const serialized = convertInputToSerializable(input);
    const deserialized = deserializeInput(serialized);

    assert.deepStrictEqual(deserialized, input);
  });

  await t.test('should deserialize attestation input', () => {
    const InputData = { age: Field, isAdmin: Bool };

    const input = Attestation.signatureNative(InputData);

    const serialized = convertInputToSerializable(input);

    const deserialized = deserializeInput(serialized);

    const reserialized = convertInputToSerializable(deserialized);

    assert.deepStrictEqual(serialized, reserialized);

    // can't compare them directly because of the verify function
    Object.entries(input).forEach(([key, value]) => {
      if (key !== 'verify') {
        assert.deepStrictEqual(deserialized[key], value);
      }
    });
  });

  await t.test('should deserialize nested input', () => {
    const input = Input.private({
      personal: {
        age: Field,
        id: UInt64,
      },
      score: UInt32,
    });
    const serialized = convertInputToSerializable(input);
    const deserialized = deserializeInput(serialized);

    assert.deepStrictEqual(deserialized, input);
  });

  await t.test('should throw error for unsupported input type', async (t) => {
    const invalidInput = { type: 'invalid' };

    try {
      deserializeInput(invalidInput);
      assert.fail('Expected an error to be thrown');
    } catch (error) {
      assert(error instanceof Error);
      assert.strictEqual(error.message, 'Invalid input type: invalid');
    }
  });
});

test('deserializeInputs', async (t) => {
  await t.test('should deserialize inputs with various type', () => {
    const inputs = {
      field: Input.private(Field),
      bool: Input.public(Bool),
      uint: Input.constant(UInt64, UInt64.from(42)),
      nested: Input.private({
        inner: Field,
        deep: {
          value: Bool,
        },
      }),
    };

    const serialized = Object.fromEntries(
      Object.entries(inputs).map(([key, value]) => [
        key,
        convertInputToSerializable(value),
      ])
    );

    const deserialized = deserializeInputs(serialized);

    assert.deepStrictEqual(deserialized, inputs);
  });

  await t.test('should deserialize attestation input', () => {
    const InputData = { age: Field, isAdmin: Bool };
    const inputs = {
      attestation: Attestation.signatureNative(InputData),
    };

    const serialized = Object.fromEntries(
      Object.entries(inputs).map(([key, value]) => [
        key,
        convertInputToSerializable(value),
      ])
    );

    const deserialized = deserializeInputs(serialized);

    const reserialized = Object.fromEntries(
      Object.entries(deserialized).map(([key, value]) => [
        key,
        convertInputToSerializable(value),
      ])
    );

    assert.deepStrictEqual(serialized, reserialized);
  });

  await t.test('should handle mixed input types', () => {
    const inputs = {
      privateField: Input.private(Field),
      publicBool: Input.public(Bool),
      constantUint: Input.constant(UInt32, UInt32.from(42)),
      attestation: Attestation.signatureNative({ score: UInt64 }),
    };

    const serialized = Object.fromEntries(
      Object.entries(inputs).map(([key, value]) => [
        key,
        convertInputToSerializable(value),
      ])
    );

    const deserialized = deserializeInputs(serialized);

    const reserialized = Object.fromEntries(
      Object.entries(deserialized).map(([key, value]) => [
        key,
        convertInputToSerializable(value),
      ])
    );

    assert.deepStrictEqual(serialized, reserialized);
  });

  await t.test('should handle empty input object', () => {
    const emptyInputs = {};
    const deserialized = deserializeInputs(emptyInputs);
    assert.deepStrictEqual(deserialized, {});
  });
});

test('deserializeNode', async (t) => {
  await t.test('should deserialize constant node', () => {
    const node: Node<Field> = { type: 'constant', data: Field(123) };
    const serialized = convertNodeToSerializable(node);
    const deserialized = deserializeNode(serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should deserialize root node', () => {
    const node: Node = {
      type: 'root',
      input: {
        age: Input.private(Field),
        isAdmin: Input.public(Bool),
      },
    };
    const serialized = convertNodeToSerializable(node);
    const deserialized = deserializeNode(serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should deserialize property node', () => {
    const node: Node = {
      type: 'property',
      key: 'age',
      inner: {
        type: 'root',
        input: {
          age: Input.private(Field),
          isAdmin: Input.public(Bool),
        },
      },
    };
    const serialized = convertNodeToSerializable(node);
    const deserialized = deserializeNode(serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should deserialize equals node', () => {
    const node: Node<Bool> = Operation.equals(
      { type: 'constant', data: Field(10) },
      { type: 'constant', data: Field(10) }
    );
    const serialized = convertNodeToSerializable(node);
    const deserialized = deserializeNode(serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should deserialize lessThan node', () => {
    const node: Node<Bool> = Operation.lessThan(
      { type: 'constant', data: UInt32.from(5) },
      { type: 'constant', data: UInt32.from(10) }
    );
    const serialized = convertNodeToSerializable(node);
    const deserialized = deserializeNode(serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should deserialize lessThanEq node', () => {
    const node: Node<Bool> = Operation.lessThanEq(
      { type: 'constant', data: UInt64.from(15) },
      { type: 'constant', data: UInt64.from(15) }
    );
    const serialized = convertNodeToSerializable(node);
    const deserialized = deserializeNode(serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should deserialize and node', () => {
    const node: Node<Bool> = Operation.and(
      { type: 'constant', data: Bool(true) },
      { type: 'constant', data: Bool(false) }
    );
    const serialized = convertNodeToSerializable(node);
    const deserialized = deserializeNode(serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should deserialize nested nodes', () => {
    const node: Node<Bool> = Operation.and(
      Operation.lessThan(
        { type: 'constant', data: Field(5) },
        { type: 'constant', data: Field(10) }
      ),
      Operation.equals(
        { type: 'constant', data: Bool(true) },
        { type: 'constant', data: Bool(true) }
      )
    );
    const serialized = convertNodeToSerializable(node);
    const deserialized = deserializeNode(serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should throw error for invalid node type', async () => {
    const invalidNode = { type: 'invalid' };

    try {
      deserializeNode(invalidNode);
      assert.fail('Expected an error to be thrown');
    } catch (error) {
      assert(error instanceof Error, 'Error should be an instance of Error');
      assert.strictEqual(
        error.message,
        'Invalid node type: invalid',
        'Error message should match expected message'
      );
    }
  });
});

test('deserializeSpec', async (t) => {
  await t.test('should correctly deserialize a simple Spec', () => {
    const originalSpec = Spec(
      {
        age: Input.private(Field),
        isAdmin: Input.public(Bool),
        maxAge: Input.constant(Field, Field(100)),
      },
      ({ age, isAdmin, maxAge }) => ({
        assert: Operation.and(Operation.lessThan(age, maxAge), isAdmin),
        data: age,
      })
    );

    const serialized = serializeSpec(originalSpec);
    const deserialized = deserializeSpec(serialized);

    assert.deepStrictEqual(deserialized.inputs, originalSpec.inputs);
    assert.deepStrictEqual(deserialized.logic, originalSpec.logic);
  });

  // it is not possible to directly compare attestations because of the verify function
  await t.test('should correctly deserialize a Spec with attestation', () => {
    const originalSpec = Spec(
      {
        signedData: Attestation.signatureNative({ field: Field }),
        zeroField: Input.constant(Field, Field(0)),
      },
      ({ signedData, zeroField }) => ({
        assert: Operation.equals(
          Operation.property(signedData, 'field'),
          zeroField
        ),
        data: signedData,
      })
    );

    const serialized = serializeSpec(originalSpec);
    const deserialized = deserializeSpec(serialized);

    const reserialized = serializeSpec(deserialized);

    assert.deepStrictEqual(serialized, reserialized);

    assert.deepStrictEqual(
      deserialized.inputs.zeroField,
      originalSpec.inputs.zeroField
    );

    assert.deepStrictEqual(
      deserialized.inputs.signedData.type,
      originalSpec.inputs.signedData.type
    );

    assert.deepStrictEqual(
      deserialized.inputs.signedData.private,
      originalSpec.inputs.signedData.private
    );
    assert.deepStrictEqual(
      deserialized.inputs.signedData.public,
      originalSpec.inputs.signedData.public
    );
    assert.deepStrictEqual(
      deserialized.inputs.signedData.data,
      originalSpec.inputs.signedData.data
    );
  });

  await t.test(
    'should correctly deserialize a Spec with nested operations',
    () => {
      const originalSpec = Spec(
        {
          field1: Input.private(Field),
          field2: Input.private(Field),
          threshold: Input.public(UInt64),
        },
        ({ field1, field2, threshold }) => ({
          assert: Operation.and(
            Operation.lessThan(field1, field2),
            Operation.lessThanEq(field2, threshold)
          ),
          data: Operation.equals(field1, field2),
        })
      );

      const serialized = serializeSpec(originalSpec);
      const deserialized = deserializeSpec(serialized);

      const reserialized = serializeSpec(deserialized);

      assert.deepStrictEqual(serialized, reserialized);

      assert.deepStrictEqual(deserialized.inputs, originalSpec.inputs);
      assert.deepStrictEqual(deserialized.logic, originalSpec.logic);
    }
  );
});
