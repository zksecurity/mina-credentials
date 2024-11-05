import {
  Bool,
  Field,
  type From,
  type InferProvable,
  Provable,
  ProvableType,
  Struct,
  UInt64,
} from 'o1js';
import { DynamicRecord } from './dynamic-record.ts';
import { DynamicString } from './dynamic-string.ts';
import { NestedProvable } from '../nested.ts';
import { mapObject, zipObjects } from '../util.ts';
import { test } from 'node:test';
import assert from 'assert';
import { hashCredential } from '../credential.ts';
import { owner } from '../../tests/test-utils.ts';
import { hashRecord } from './dynamic-hash.ts';
import { array } from '../o1js-missing.ts';
import { DynamicArray } from './dynamic-array.ts';

const String10 = DynamicString({ maxLength: 10 });

// original schema, data and hash from known layout

const OriginalSchema = Schema({
  first: Field,
  second: Bool,
  third: String10,
  fourth: UInt64,
  fifth: { field: Field, string: String10 },
  sixth: array(Field, 3),
});

let input = {
  first: 1,
  second: true,
  third: 'something',
  fourth: 123n,
  fifth: { field: 2, string: '...' },
  sixth: [1n, 2n, 3n],
};

let original = OriginalSchema.from(input);
const expectedHash = hashRecord(original);

const OriginalWrappedInStruct = Struct(OriginalSchema.schema);
let originalStruct = OriginalWrappedInStruct.fromValue(input);

// subset schema and circuit that doesn't know the full original layout

// not necessarily matches the length of the original schema
const String20 = DynamicString({ maxLength: 20 });
const String5 = DynamicString({ maxLength: 5 });

const Fifth = DynamicRecord(
  {
    // _nested_ subset of original schema
    string: String5, // different max length here as well
  },
  { maxEntries: 5 }
);

const Subschema = DynamicRecord(
  {
    // not necessarily in order
    third: String20,
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
    // static field
    record.get('first').assertEquals(1, 'first');

    // dynamic string with different max length
    Provable.assertEqual(
      String20,
      record.get('third'),
      String20.from('something')
    );

    // nested subschema
    let fifthString = record.get('fifth').get('string');
    Provable.assertEqual(String5, fifthString, String5.from('...'));
  });

  await test('DynamicRecord.getAny()', () => {
    record.getAny(Bool, 'second').assertEquals(true, 'second');
    record.getAny(UInt64, 'fourth').assertEquals(UInt64.from(123n));

    // this works because structs are hashed in dynamic record style,
    // and the string is hashed in dynamic array style
    const FifthStruct = Struct({ field: Field, string: String20 });
    Provable.assertEqual(
      FifthStruct,
      record.getAny(FifthStruct, 'fifth'),
      FifthStruct.fromValue({ field: 2, string: '...' })
    );

    const SixthDynamic = DynamicArray(Field, { maxLength: 7 });
    Provable.assertEqual(
      SixthDynamic,
      record.getAny(SixthDynamic, 'sixth'),
      SixthDynamic.from([1n, 2n, 3n])
    );

    assert.throws(() => record.getAny(Bool, 'missing'), /Key not found/);
  });

  await test('DynamicRecord.hash()', () =>
    record.hash().assertEquals(expectedHash, 'hash'));

  await test('hashRecord()', () => {
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
  };
}
