import {
  Bool,
  Field,
  type From,
  type InferProvable,
  Poseidon,
  Provable,
  ProvableType,
  Struct,
  UInt64,
} from 'o1js';
import {
  DynamicRecord,
  packToField,
  packStringToField,
  hashRecord,
} from './dynamic-record.ts';
import { DynamicString } from './dynamic-string.ts';
import { NestedProvable } from '../nested.ts';
import { mapEntries, mapObject, zip, zipObjects } from '../util.ts';
import { test } from 'node:test';
import assert from 'assert';
import { hashCredential } from '../credential.ts';
import { owner } from '../../tests/test-utils.ts';

const String = DynamicString({ maxLength: 10 });

// original schema, data and hash from known layout

const OriginalSchema = Schema({
  first: Field,
  second: Bool,
  third: String,
  fourth: UInt64,
  fifth: { field: Field, string: String },
});

let input = {
  first: 1,
  second: true,
  third: 'something',
  fourth: 123n,
  fifth: { field: 2, string: '...' },
};

let original = OriginalSchema.from(input);
const expectedHash = OriginalSchema.hash(original);

const OriginalWrappedInStruct = Struct(OriginalSchema.schema);
let originalStruct = OriginalWrappedInStruct.fromValue(input);

// subset schema and circuit that doesn't know the full original layout

const Fifth = DynamicRecord(
  { field: Field, string: String },
  { maxEntries: 5 }
);

const Subschema = DynamicRecord(
  {
    // not necessarily in order
    third: DynamicString({ maxLength: 10 }),
    fifth: Fifth,
    first: Field,
  },
  { maxEntries: 10 }
);

// original schema is compatible
Subschema.from(original);
Subschema.from(originalStruct);

async function circuit() {
  let record = Provable.witness(Subschema, () => original);

  await test('DynamicRecord.get()', () => {
    record.get('first').assertEquals(1, 'first');
    Provable.assertEqual(String, record.get('third'), String.from('something'));

    Provable.assertEqual(
      Fifth,
      record.get('fifth'),
      Fifth.from({ field: 2, string: '...' })
    );
  });

  await test('DynamicRecord.getAny()', () => {
    record.getAny(Bool, 'second').assertEquals(true, 'second');
    record.getAny(UInt64, 'fourth').assertEquals(UInt64.from(123n));

    // this works because structs are hashed in dynamic record form
    const FifthStruct = Struct({ field: Field, string: String });
    Provable.assertEqual(
      FifthStruct,
      record.getAny(FifthStruct, 'fifth'),
      FifthStruct.fromValue({ field: 2, string: '...' })
    );

    assert.throws(() => record.getAny(Bool, 'missing'), /Key not found/);
  });

  await test('DynamicRecord.hash()', () =>
    record.hash().assertEquals(expectedHash, 'hash'));

  await test('hashRecord()', () => {
    hashRecord(original).assertEquals(expectedHash);
    hashRecord(originalStruct).assertEquals(expectedHash);
    hashRecord(record).assertEquals(expectedHash);
  });

  await test('hashCredential()', () => {
    let originalHash = hashCredential(OriginalSchema.schema, {
      owner,
      data: original,
    }).hash;

    let originalStructHash = hashCredential(OriginalWrappedInStruct, {
      owner,
      data: originalStruct,
    }).hash;

    originalStructHash.assertEquals(originalHash, 'hashCredential() (struct)');

    let subschemaHash = hashCredential(Subschema, {
      owner,
      data: record,
    }).hash;

    subschemaHash.assertEquals(
      originalHash,
      'hashCredential() (dynamic record)'
    );
  });
}

await test('outside circuit', () => circuit());
await test('inside circuit', () => Provable.runAndCheck(circuit));

// could also use `Struct` instead of `Schema`,
// but `Schema.from()` returns a plain object which is slightly more idiomatic
function Schema<A extends Record<string, NestedProvable>>(schema: A) {
  let shape = mapObject<A, { [K in keyof A]: Provable<InferProvable<A[K]>> }>(
    schema,
    (type) => NestedProvable.get(type)
  );
  return {
    schema,

    from(value: { [K in keyof A]: From<A[K]> }) {
      let actual: { [K in keyof A]: InferProvable<A[K]> } = mapObject(
        zipObjects(shape, value),
        ([type, value]) => ProvableType.get(type).fromValue(value)
      );
      return actual;
    },

    hash(value: { [K in keyof A]: From<A[K]> }) {
      let normalized = this.from(value);
      let entryHashes = mapEntries(
        zipObjects(shape, normalized),
        (key, [type, value]) => [
          packStringToField(key),
          packToField(type, value),
        ]
      );
      return Poseidon.hash(entryHashes.flat());
    },
  };
}
