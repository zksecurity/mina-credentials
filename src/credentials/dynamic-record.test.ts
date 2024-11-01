import {
  Bool,
  Field,
  type From,
  type InferProvable,
  ProvableType,
  UInt64,
} from 'o1js';
import { DynamicRecord } from './dynamic-record.ts';
import { DynamicString } from './dynamic-string.ts';
import { NestedProvable } from '../nested.ts';
import { mapObject, zipObjects } from '../util.ts';
import assert from 'node:assert';
import test from 'node:test';

const String = DynamicString({ maxLength: 10 });

const OriginalSchema = Schema({
  first: Field,
  second: Bool,
  third: String,
  fourth: UInt64,
  fifth: { field: Field, string: String },
});

let original = OriginalSchema.from({
  first: 1,
  second: true,
  third: 'something',
  fourth: 123n,
  fifth: { field: 2, string: '...' },
});

const Subschema = DynamicRecord(
  // subset, not necessarily in order
  {
    fourth: UInt64,
    third: DynamicString({ maxLength: 10 }),
    first: Field,
  },
  { maxEntries: 10, maxKeyLength: 20, maxValueLength: 20 }
);

let record = Subschema.from(original);

test('DynamicRecord.get()', () =>
  assert.deepStrictEqual(
    {
      first: record.get('first').toBigInt(),
      third: record.get('third').toString(),
      fourth: record.get('fourth').toBigInt(),
    },
    { first: 1n, third: 'something', fourth: 123n }
  ));

// could also use `Struct` instead of `Schema`,
// but `Schema.from()` returns a plain object which is slightly more idiomatic
function Schema<A extends Record<string, NestedProvable>>(schema: A) {
  let shape = mapObject(schema, (type) => NestedProvable.get(type));
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
