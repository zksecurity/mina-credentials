import {
  type Bool,
  type From,
  type InferProvable,
  type InferValue,
  type ProvableHashable,
  UInt64,
} from 'o1js';
import { assert, mapObject, zipObjects } from '../util.ts';
import {
  type ProvableHashableType,
  type ProvableHashableWide,
  ProvableType,
} from '../o1js-missing.ts';
import { provableTypeOf } from './dynamic-hash.ts';
import { NestedProvable } from '../nested.ts';
import type { DynamicString } from './dynamic-string.ts';
import type { DynamicArrayClass } from './dynamic-array.ts';
import type { DynamicRecordClass } from './dynamic-record.ts';

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

Schema.String = { type: 'string' } satisfies SchemaType;
Schema.Number = { type: 'number' } satisfies SchemaType;
Schema.Boolean = { type: 'boolean' } satisfies SchemaType;
Schema.Array = function SchemaArray<T extends SchemaType>(
  inner: T
): SchemaArray<T> {
  return { type: 'array', inner };
};

function Schema<T extends Record<string, SchemaType>>(schema: T) {
  return {
    schema,

    from(value: SchemaInput<T>): SchemaOutput<T> {
      return validateAndConvert(schema, value);
    },

    nestedType(value: SchemaOutput<T>): {
      [key in keyof T]: ProvableTypeOf<T[key]>;
    } {
      return mapObject<any, any>(value, (v: unknown) => provableTypeOf(v));
    },

    type(value: SchemaOutput<T>): ProvableHashableWide<
      {
        [key in keyof T]: InferProvable<ProvableTypeOf<T[key]>>;
      },
      {
        [key in keyof T]: InferValue<ProvableTypeOf<T[key]>>;
      },
      {
        [key in keyof T]: From<ProvableTypeOf<T[key]>>;
      }
    > {
      return NestedProvable.get(this.nestedType(value) as any) as any;
    },
  };
}

// loosely-typed versions of the above functions that work without a schema object

Schema.nestedType = function nestedType<S>(value: S): unknown extends S
  ? NestedProvable
  : {
      [key in keyof S]: ProvableHashableType<S[key], S[key]>;
    } {
  return mapObject<any, any>(value, (v: unknown) => provableTypeOf(v));
};
Schema.type = function type<S>(value: S): ProvableHashable<S, S> {
  return NestedProvable.get(Schema.nestedType(value));
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

type SchemaInput<T = SchemaType> = T extends ProvableHashableType
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

/**
 * Type version of `provableTypeOf()`.
 */
type ProvableTypeOf<T> = T extends ProvableHashableType
  ? T
  : T extends SchemaString
  ? ReturnType<typeof DynamicString>
  : T extends SchemaNumber
  ? typeof UInt64
  : T extends SchemaBoolean
  ? typeof Bool
  : T extends SchemaArray<infer U>
  ? DynamicArrayClass<
      InferProvable<ProvableTypeOf<U>>,
      InferValue<ProvableTypeOf<U>>
    >
  : T extends { [key in string]: SchemaType }
  ? DynamicRecordClass<{ [key in keyof T]: ProvableTypeOf<T[key]> }>
  : never;
