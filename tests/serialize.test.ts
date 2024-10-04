import { test } from 'node:test';
import assert from 'node:assert';
import {
  Input,
  Attestation,
  Operation,
  Spec,
  Node,
} from '../src/program-config.ts';

import {
  serializeProvableType,
  serializeNestedProvableFor,
  convertNodeToSerializable,
  convertInputToSerializable,
} from '../src/serialize-spec.ts';
import {
  Bool,
  Bytes,
  Field,
  Provable,
  PublicKey,
  Signature,
  Struct,
  UInt32,
  UInt64,
  UInt8,
  VerificationKey,
} from 'o1js';

test('Serialize Inputs', async (t) => {
  await t.test('should serialize basic types correctly', () => {
    assert.deepStrictEqual(serializeProvableType(Field), { type: 'Field' });
    assert.deepStrictEqual(serializeProvableType(Bool), { type: 'Bool' });
    assert.deepStrictEqual(serializeProvableType(UInt8), { type: 'UInt8' });
    assert.deepStrictEqual(serializeProvableType(UInt32), { type: 'UInt32' });
    assert.deepStrictEqual(serializeProvableType(UInt64), { type: 'UInt64' });
    assert.deepStrictEqual(serializeProvableType(PublicKey), {
      type: 'PublicKey',
    });
    assert.deepStrictEqual(serializeProvableType(Signature), {
      type: 'Signature',
    });
  });

  await t.test('should serialize structs correctly', () => {
    // TODO: implement
  });

  await t.test('should serialize simple provable types (nested)', () => {
    assert.deepStrictEqual(serializeNestedProvableFor(Field), {
      type: 'Field',
    });
    assert.deepStrictEqual(serializeNestedProvableFor(Bool), { type: 'Bool' });
    assert.deepStrictEqual(serializeNestedProvableFor(UInt8), {
      type: 'UInt8',
    });
    assert.deepStrictEqual(serializeNestedProvableFor(UInt32), {
      type: 'UInt32',
    });
    assert.deepStrictEqual(serializeNestedProvableFor(UInt64), {
      type: 'UInt64',
    });
    assert.deepStrictEqual(serializeNestedProvableFor(PublicKey), {
      type: 'PublicKey',
    });
    assert.deepStrictEqual(serializeNestedProvableFor(Signature), {
      type: 'Signature',
    });
  });

  await t.test('should serialize nested objects with provable types', () => {
    const nestedType = {
      field: Field,
      nested: {
        uint: UInt32,
        bool: Bool,
      },
    };

    assert.deepStrictEqual(serializeNestedProvableFor(nestedType), {
      field: { type: 'Field' },
      nested: {
        bool: { type: 'Bool' },
        uint: { type: 'UInt32' },
      },
    });
  });

  await t.test('should serialize complex nested structures', () => {
    const complexType = {
      simpleField: Field,
      nestedObject: {
        publicKey: PublicKey,
        signature: Signature,
        deeplyNested: {
          bool: Bool,
          uint64: UInt64,
        },
      },
    };

    assert.deepStrictEqual(serializeNestedProvableFor(complexType), {
      simpleField: { type: 'Field' },
      nestedObject: {
        publicKey: { type: 'PublicKey' },
        signature: { type: 'Signature' },
        deeplyNested: {
          bool: { type: 'Bool' },
          uint64: { type: 'UInt64' },
        },
      },
    });
  });

  await t.test('should throw an error for unsupported types', () => {
    assert.throws(() => serializeNestedProvableFor('unsupported' as any), {
      name: 'Error',
      message: 'Unsupported type in NestedProvableFor: unsupported',
    });
  });
});

test('Serialize Nodes', async (t) => {
  await t.test('should serialize constant Node', () => {
    const constantNode: Node<Field> = { type: 'constant', data: Field(123) };

    const serialized = convertNodeToSerializable(constantNode);

    const expected = {
      type: 'constant',
      data: {
        type: 'Field',
        value: '123',
      },
    };

    assert.deepEqual(serialized, expected);
  });
});

test('convertInputToSerializable', async (t) => {
  await t.test('should serialize constant input', () => {
    const input = Input.constant(Field, Field(42));

    const serialized = convertInputToSerializable(input);

    const expected = {
      type: 'constant',
      data: { type: 'Field' },
      value: '42',
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize public input', () => {
    const input = Input.public(Field);

    const serialized = convertInputToSerializable(input);

    const expected = {
      type: 'public',
      data: { type: 'Field' },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize private input', () => {
    const input = Input.private(Field);
    const serialized = convertInputToSerializable(input);
    const expected = {
      type: 'private',
      data: { type: 'Field' },
    };
    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize attestation input', () => {
    const InputData = { age: Field, isAdmin: Bool };
    const input = Attestation.signature(InputData);
    const serialized = convertInputToSerializable(input);
    const expected = {
      type: 'attestation',
      id: 'native-signature',
      public: { type: 'PublicKey' },
      private: { type: 'Signature' },
      data: {
        age: { type: 'Field' },
        isAdmin: { type: 'Bool' },
      },
    };
    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize nested input', () => {
    const NestedInputData = {
      personal: {
        age: Field,
        id: UInt64,
      },
      score: UInt32,
    };
    const input = Input.private(NestedInputData);
    const serialized = convertInputToSerializable(input);
    const expected = {
      type: 'private',
      data: {
        personal: {
          age: { type: 'Field' },
          id: { type: 'UInt64' },
        },
        score: { type: 'UInt32' },
      },
    };
    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should throw error for unsupported input type', () => {
    const invalidInput = { type: 'invalid' } as any;
    assert.throws(() => convertInputToSerializable(invalidInput), {
      name: 'Error',
      message: 'Invalid input type',
    });
  });
});
