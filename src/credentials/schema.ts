import { Bool, Field, type From, type InferProvable, UInt64 } from 'o1js';
import { assert, mapObject, stringLength, zipObjects } from '../util.ts';
import { type ProvableHashableType, ProvableType } from '../o1js-missing.ts';
import { DynamicString } from './dynamic-string.ts';
import { DynamicArray } from './dynamic-array.ts';
import { innerArrayType, provableTypeOf } from './dynamic-hash.ts';
import type { NestedProvableFor } from '../nested.ts';

export { Schema };

type SchemaType =
  | ProvableHashableType
  | SchemaString
  | SchemaNumber
  | SchemaBoolean
  | SchemaBigint
  | { type: 'array'; inner: SchemaType }
  | { [key in string]: SchemaType };

type SchemaString = { type: 'string' };
type SchemaNumber = { type: 'number' };
type SchemaBoolean = { type: 'boolean' };
type SchemaBigint = { type: 'bigint' };
type SchemaArray<T extends SchemaType = SchemaType> = {
  type: 'array';
  inner: T;
};

function Schema<T extends Record<string, SchemaType>>(
  schema: T
): {
  schema: T;

  from(value: SchemaInput<T>): SchemaOutput<T>;

  type(value: SchemaOutput<T>): {
    [key in keyof T]: ProvableHashableType<SchemaOutput<T>[key]>;
  };
} {
  return {
    schema,

    from(value) {
      return (validateAndConvert as any)(schema, value);
    },

    type(value) {
      return mapObject<any, any>(value, (v: unknown) => provableTypeOf(v));
    },
  };
}

Schema.String = { type: 'string' } satisfies SchemaType;
Schema.Number = { type: 'number' } satisfies SchemaType;
Schema.Boolean = { type: 'boolean' } satisfies SchemaType;
Schema.Bigint = { type: 'bigint' } satisfies SchemaType;
Schema.Array = function SchemaArray<T extends SchemaType>(
  inner: T
): SchemaArray<T> {
  return { type: 'array', inner };
};

function validateAndConvert(schema: SchemaType, value: unknown): any {
  if (ProvableType.isProvableHashableType(schema)) {
    return ProvableType.get(schema).fromValue(value);
  }
  switch (schema.type) {
    case 'string':
      assert(typeof value === 'string');
      return DynamicString({ maxLength: stringLength(value) }).from(value);
    case 'number':
      assert(typeof value === 'number');
      assert(Number.isInteger(value));
      return UInt64.from(value);
    case 'boolean':
      assert(typeof value === 'boolean');
      return Bool(value);
    case 'bigint':
      assert(typeof value === 'bigint');
      return Field(value);
    case 'array':
      assert(Array.isArray(value));
      let innerType = innerArrayType(value);
      return DynamicArray(innerType, { maxLength: value.length }).from(
        value.map((v: unknown) => validateAndConvert(schema.inner, v))
      );
    default:
      assert(typeof value === 'object' && value !== null);
      return mapObject(zipObjects(schema, value), ([s, v]) =>
        validateAndConvert(s, v)
      );
  }
}

type SchemaInput<T extends SchemaType = SchemaType> =
  T extends ProvableHashableType
    ? From<T>
    : T extends SchemaString
    ? string
    : T extends SchemaNumber
    ? number
    : T extends SchemaBoolean
    ? boolean
    : T extends SchemaBigint
    ? bigint
    : T extends SchemaArray<infer U>
    ? SchemaInput<U>[]
    : T extends { [key in string]: SchemaType }
    ? { [key in keyof T]: SchemaInput<T[key]> }
    : never;

// TODO: this type is somehow breaking TS completely
type SchemaOutput<T = SchemaType> = T extends ProvableHashableType
  ? InferProvable<T>
  : T extends SchemaString
  ? DynamicString
  : T extends SchemaNumber
  ? UInt64
  : T extends SchemaBoolean
  ? Bool
  : T extends SchemaBigint
  ? Field
  : T extends SchemaArray<infer U>
  ? DynamicArray<SchemaOutput<U>>
  : { [key in keyof T]: SchemaOutput<T[key]> };
