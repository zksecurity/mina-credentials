/**
 * Hashing of arbitrary data types compatible with dynamic-length schemas.
 */
import {
  Bool,
  Bytes,
  Field,
  Poseidon,
  Struct,
  UInt64,
  UInt8,
  Undefined,
} from 'o1js';
import {
  type ProvableHashableType,
  ProvableType,
  toFieldsPacked,
} from '../o1js-missing.ts';
import { assert, hasProperty, isSubclass, mapEntries } from '../util.ts';
import { NestedProvable } from '../nested.ts';
import type { UnknownRecord } from './dynamic-record.ts';
import { BaseType } from './dynamic-base-types.ts';

export {
  hashDynamic,
  hashArray,
  hashString,
  packStringToField,
  packToField,
  hashRecord,
  bitSize,
  packedFieldSize,
};

// compatible hashing

type HashableValue =
  | undefined
  | string
  | number
  | boolean
  | bigint
  | HashableValue[]
  | { [key in string]: HashableValue };

function hashDynamic(value: HashableValue) {
  if (typeof value === 'string') return hashString(value);
  if (typeof value === 'number') return packToField(UInt64.from(value), UInt64);
  if (typeof value === 'boolean') return packToField(Bool(value), Bool);
  if (typeof value === 'bigint') return packToField(Field(value), Field);
  if (Array.isArray(value)) return hashArray(value);
  return hashRecord(value);
}

const simpleTypes = new Set(['number', 'boolean', 'bigint', 'undefined']);

function isSimple(
  value: unknown
): value is number | boolean | bigint | undefined {
  return simpleTypes.has(typeof value);
}

function provableTypeOf(value: HashableValue): ProvableHashableType {
  if (value === undefined) return Undefined;
  if (typeof value === 'string') {
    return BaseType.DynamicString({ maxLength: value.length });
  }
  if (typeof value === 'number') return UInt64;
  if (typeof value === 'boolean') return Bool;
  if (typeof value === 'bigint') return Field;
  if (Array.isArray(value)) {
    return BaseType.DynamicArray(innerArrayType(value), {
      maxLength: value.length,
    });
  }
  return BaseType.DynamicRecord({}, { maxEntries: Object.keys(value).length });
}

function provableTypeEquals(
  value: HashableValue,
  type: ProvableHashableType
): boolean {
  if (isSimple(value)) return provableTypeOf(value) === type;
  if (typeof value === 'string') {
    return isSubclass(type, BaseType.DynamicString.Base);
  }
  if (Array.isArray(value)) {
    if (!isSubclass(type, BaseType.DynamicArray.Base)) return false;
    let innerType = type.prototype.innerType;
    return value.every((v) => provableTypeEquals(v, innerType));
  }
  return isSubclass(type, BaseType.GenericRecord.Base);
}

function innerArrayType(array: HashableValue[]): ProvableHashableType {
  let type = provableTypeOf(array[0]);
  assert(
    array.every((v) => {
      return provableTypeEquals(v, type);
    }),
    'Array elements must be homogenous'
  );
  return type;
}

function hashArray(array: HashableValue[]) {
  let type = innerArrayType(array);
  let Array = BaseType.DynamicArray(type, { maxLength: array.length });
  let as = Array.from(array);
  // TODO remove
  console.dir(as, { depth: 4 });
  return as.hash();
}

const enc = new TextEncoder();

function hashString(string: string) {
  // encode length + bytes
  let stringBytes = enc.encode(string);
  let length = stringBytes.length;
  let bytes = new Uint8Array(4 + length);
  new DataView(bytes.buffer).setUint32(0, length, true);
  bytes.set(stringBytes, 4);
  let B = Bytes(4 + length);
  let fields = toFieldsPacked(B, B.from(bytes));
  return Poseidon.hash(fields);
}

function packStringToField(string: string) {
  let bytes = enc.encode(string);
  let B = Bytes(bytes.length);
  let fields = toFieldsPacked(B, B.from(bytes));
  if (fields.length === 1) return fields[0]!;
  return Poseidon.hash(fields);
}

function packToField<T>(value: T, type?: ProvableType<T>): Field {
  // hashable values
  if (isSimple(value) || typeof value === 'string' || Array.isArray(value)) {
    return hashDynamic(value);
  }

  // dynamic array types
  if (value instanceof BaseType.DynamicArray.Base) {
    return value.hash();
  }

  type ??= NestedProvable.get(NestedProvable.fromValue(value));

  // record types
  if (isStruct(type) || value instanceof BaseType.GenericRecord.Base) {
    return hashRecord(value);
  }

  let fields = toFieldsPacked(type, value);
  if (fields.length === 1) return fields[0]!;
  return Poseidon.hash(fields);
}

function hashRecord(data: unknown) {
  if (data instanceof BaseType.GenericRecord.Base) return data.hash();
  assert(
    typeof data === 'object' && data !== null,
    'Expected DynamicRecord or plain object as data'
  );
  let entryHashes = mapEntries(data as UnknownRecord, (key, value) => {
    let type = NestedProvable.get(NestedProvable.fromValue(value));
    return [packStringToField(key), packToField(value, type)];
  });
  return Poseidon.hash(entryHashes.flat());
}

// helpers

function isStruct(type: ProvableType): type is Struct<any> {
  return (
    hasProperty(type, '_isStruct') &&
    type._isStruct === true &&
    // this shouldn't have been implemented as struct, it's just 1 field
    type !== UInt8
  );
}

function bitSize(type: ProvableHashableType): number {
  let provable = ProvableType.get(type);
  let { fields = [], packed = [] } = provable.toInput(provable.empty());
  let nBits = fields.length * Field.sizeInBits;
  for (let [, size] of packed) {
    nBits += size;
  }
  return nBits;
}

function packedFieldSize(type: ProvableHashableType): number {
  let provable = ProvableType.get(type);
  let { fields = [], packed = [] } = provable.toInput(provable.empty());
  let nFields = fields.length;
  let pendingBits = 0;
  for (let [, size] of packed) {
    pendingBits += size;
    if (pendingBits >= Field.sizeInBits) {
      nFields++;
      pendingBits -= Field.sizeInBits;
    }
  }
  if (pendingBits > 0) nFields++;
  return nFields;
}
