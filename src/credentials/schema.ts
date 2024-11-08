import {
  type From,
  type InferProvable,
  type ProvableHashable,
  UInt64,
} from 'o1js';
import { assert, mapObject, zipObjects } from '../util.ts';
import { type ProvableHashableType, ProvableType } from '../o1js-missing.ts';
import { provableTypeOf } from './dynamic-hash.ts';
import { NestedProvable } from '../nested.ts';

export { Schema };

type SchemaType =
  | ProvableHashableType
  | SchemaString
  | SchemaNumber
  | SchemaBoolean
  | { type: 'array'; inner: SchemaType }
  | { [key in string]: SchemaType };

type SchemaString = { type: 'string' };
type SchemaNumber = { type: 'number' };
type SchemaBoolean = { type: 'boolean' };
type SchemaArray<T extends SchemaType = SchemaType> = {
  type: 'array';
  inner: T;
};

function Schema<T extends Record<string, SchemaType>>(schema: T) {
  return {
    schema,

    from(value: SchemaInput<T>): SchemaOutput<T> {
      return validateAndConvert(schema, value);
    },
  };
}
Schema.nestedType = function nestedType<S extends SchemaOutput<unknown>>(
  value: S
): {
  [key in keyof S]: ProvableHashableType<S[key], S[key]>;
} {
  return mapObject<any, any>(value, (v: unknown) => provableTypeOf(v));
};
Schema.type = function type<S extends SchemaOutput<unknown>>(
  value: S
): ProvableHashable<S, S> {
  return NestedProvable.get(Schema.nestedType(value));
};

Schema.String = { type: 'string' } satisfies SchemaType;
Schema.Number = { type: 'number' } satisfies SchemaType;
Schema.Boolean = { type: 'boolean' } satisfies SchemaType;
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
      return value;
    case 'number':
      assert(typeof value === 'number');
      assert(Number.isInteger(value));
      return UInt64.from(value);
    case 'boolean':
      assert(typeof value === 'boolean');
      return value;
    case 'array':
      assert(Array.isArray(value));
      return value.map((v) => validateAndConvert(schema.inner, v));
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
    : T extends SchemaArray<infer U>
    ? SchemaInput<U>[]
    : T extends { [key in string]: SchemaType }
    ? { [key in keyof T]: SchemaInput<T[key]> }
    : never;

// TODO: this type is hard for TS to process
type SchemaOutput<T = SchemaType> = T extends ProvableHashableType
  ? InferProvable<T>
  : T extends SchemaString
  ? string
  : T extends SchemaNumber
  ? UInt64
  : T extends SchemaBoolean
  ? boolean
  : T extends SchemaArray<infer U>
  ? SchemaOutput<U>[]
  : { [key in keyof T]: SchemaOutput<T[key]> };
