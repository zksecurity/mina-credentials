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
import { hashDynamic, hashRecord } from './dynamic-hash.ts';
import { array } from '../o1js-missing.ts';
import { DynamicArray } from './dynamic-array.ts';
import { Schema } from './schema.ts';

const String5 = DynamicString({ maxLength: 5 });
const String10 = DynamicString({ maxLength: 10 });
const String20 = DynamicString({ maxLength: 20 });

// original schema, data and hash from known layout

const OriginalSchema = Schema({
  first: Field,
  second: Bool,
  third: Schema.String,
  fourth: UInt64,
  fifth: { field: Field, string: String10 },
  sixth: Schema.Array(Schema.Bigint),
});

let original = OriginalSchema.from({
  first: 1,
  second: true,
  third: 'something',
  fourth: 123n,
  fifth: { field: 2, string: '...' },
  sixth: [1n, 2n, 3n],
});
const expectedHash = hashRecord(original);

const OriginalWrappedInStruct = Struct(Schema.nestedType(original));
let originalStruct = OriginalWrappedInStruct.fromValue(original);

console.dir({ original, originalStruct }, { depth: 6 });

// subset schema and circuit that doesn't know the full original layout

const Subschema = DynamicRecord(
  {
    // different max length of string/array properties
    third: String20,
    // not necessarily in original order
    first: Field,
    // subset in nested schema
    fifth: DynamicRecord(
      {
        // different max length here as well
        string: String5,
      },
      { maxEntries: 5 }
    ),
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
    record.get('third').assertEqualsStrict(String20.from('something'));

    // nested subschema
    let fifthString = record.get('fifth').get('string');
    fifthString.assertEqualsStrict(String5.from('...'));
  });

  await test('DynamicRecord.getAny()', () => {
    // we can get the other fields as well, if we know their type
    record.getAny(Bool, 'second').assertEquals(true, 'second');
    record.getAny(UInt64, 'fourth').assertEquals(UInt64.from(123n));

    // `packToField()` collisions mean that we can also reinterpret fields into types with equivalent packing
    // (if the new type's `fromValue()` allows the original value)
    record.getAny(Bool, 'first').assertEquals(true, 'first');
    record.getAny(UInt64, 'first').assertEquals(UInt64.one);

    // we can get a nested record as struct (and nested strings can have different length)
    // this works because structs are hashed in dynamic record style
    const FifthStruct = Struct({ field: Field, string: String20 });
    let fifth = record.getAny(FifthStruct, 'fifth');
    Provable.assertEqual(
      FifthStruct,
      fifth,
      FifthStruct.fromValue(original.fifth)
    );

    // can get an array as dynamic array, as long as the maxLength is >= the actual length
    const SixthDynamic = DynamicArray(Field, { maxLength: 7 });
    let sixth = record.getAny(SixthDynamic, 'sixth');
    sixth.assertEqualsStrict(SixthDynamic.from(original.sixth));

    const SixthDynamicShort = DynamicArray(Field, { maxLength: 2 });
    assert.throws(
      () => record.getAny(SixthDynamicShort, 'sixth'),
      /larger than target size/
    );

    // can't get a missing key
    assert.throws(() => record.getAny(Bool, 'missing'), /Key not found/);
  });

  await test('DynamicRecord.hash()', () =>
    record.hash().assertEquals(expectedHash, 'hash'));

  await test('hashDynamic()', () => {
    hashDynamic(original).assertEquals(expectedHash);
    hashDynamic(originalStruct).assertEquals(expectedHash);
    hashDynamic(record).assertEquals(expectedHash);
  });

  await test('hashCredential()', () => {
    let type = Schema.type(original);
    let originalHash = hashCredential(type, {
      owner,
      data: type.fromValue(original),
    }).hash;

    let originalStructHash = hashCredential(OriginalWrappedInStruct, {
      owner,
      data: originalStruct,
    }).hash;

    originalStructHash.assertEquals(originalHash, 'hashCredential() (struct)');

    let subschemaHash = hashCredential(Subschema, { owner, data: record }).hash;
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
// function Schema<A extends Record<string, NestedProvable>>(schema: A) {
//   let shape = mapObject<A, { [K in keyof A]: Provable<InferProvable<A[K]>> }>(
//     schema,
//     (type) => NestedProvable.get(type)
//   );
//   return {
//     schema,

//     from(value: { [K in keyof A]: From<A[K]> }) {
//       let actual: { [K in keyof A]: InferProvable<A[K]> } = mapObject(
//         zipObjects(shape, value),
//         ([type, value]) => ProvableType.get(type).fromValue(value)
//       );
//       return actual;
//     },
//   };
// }
