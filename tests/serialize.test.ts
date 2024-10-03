import { test } from 'node:test';
import assert from 'node:assert';
import { Input, Attestation } from '../src/program-config.ts';

import { serializeProvableType } from '../src/serialize-spec.ts';
import { Bool, Field, PublicKey, Signature, UInt32, UInt64, UInt8 } from 'o1js';

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
});
