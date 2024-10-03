import { test } from 'node:test';
import assert from 'node:assert';
import { Input, Attestation, Operation, Spec } from '../src/program-config.ts';

import {
  serializeProvableType,
  serializeNestedProvableFor,
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

test('Serialize spec and related types', async (t) => {
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
