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
  hashPacked,
  type ProvableHashableType,
  ProvableType,
  toFieldsPacked,
} from '../o1js-missing.ts';
import {
  assert,
  hasProperty,
  isSubclass,
  mapEntries,
  stringLength,
} from '../util.ts';
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

/**
 * Hash an input that is either a simple JSON-with-bigints object or a provable type.
 *
 * The hashing algorithm is compatible with dynamic-length schemas.
 */
function hashDynamic(value: HashableValue | unknown) {
  return packToField(value, undefined, { mustHash: true });
}

function packToField<T>(
  value: T,
  type?: ProvableHashableType<T>,
  config?: { mustHash: boolean }
): Field {
  // hashable values
  if (typeof value === 'string') return hashString(value);
  if (typeof value === 'number')
    return packToField(UInt64.from(value), UInt64, config);
  if (typeof value === 'boolean') return packToField(Bool(value), Bool, config);
  if (typeof value === 'bigint')
    return packToField(Field(value), Field, config);
  if (value === undefined || value === null)
    return hashPacked(Undefined, undefined);

  // dynamic array types
  if (Array.isArray(value)) {
    return hashArray(value);
  }
  if (value instanceof BaseType.DynamicArray.Base) {
    return value.hash();
  }
  // dynamic records
  if (value instanceof BaseType.GenericRecord.Base) {
    return value.hash();
  }

  // now let's try to get the type from the value
  type ??= provableTypeOfConstructor<T>(value);

  if (type !== undefined) {
    // handle structs as dynamic records
    if (isStruct(type)) return hashRecord(value);

    // other provable types use directly
    let fields = toFieldsPacked(type, value);
    if (fields.length === 1 && !config?.mustHash) return fields[0]!;
    return Poseidon.hash(fields);
  }

  // at this point, the only valid types are records
  // functions are a hint that something went wrong, so throw a descriptive error
  assert(typeof value === 'object', `Failed to get type for value ${value}`);
  return hashRecord(value);
}

function hashArray(array: unknown[]) {
  let type = innerArrayType(array);
  let Array = BaseType.DynamicArray(type, { maxLength: array.length });
  return Array.from(array).hash();
}

function hashRecord(data: {}) {
  assert(typeof data === 'object', 'Expected plain object');
  let entryHashes = mapEntries(data as UnknownRecord, (key, value) => {
    return [packStringToField(key), packToField(value)];
  });
  return Poseidon.hash(entryHashes.flat());
}

const enc = new TextEncoder();

/**
 * Hash a string using Poseidon on packed UInt8s.
 *
 * Avoids hash collisions by encoding the length of the string at the beginning.
 */
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

/**
 * Gets a provable type from any value.
 *
 * The fallback type for unknown objects is DynamicRecord.
 */
function provableTypeOf(value: unknown): ProvableHashableType {
  if (typeof value === 'string') {
    return BaseType.DynamicString({ maxLength: stringLength(value) });
  }
  if (typeof value === 'number') return UInt64;
  if (typeof value === 'boolean') return Bool;
  if (typeof value === 'bigint') return Field;
  if (value === undefined || value === null) return Undefined;
  if (Array.isArray(value)) {
    return BaseType.DynamicArray(innerArrayType(value), {
      maxLength: value.length,
    });
  }
  let type = provableTypeOfConstructor(value);

  // handle structs and unknown objects as dynamic records
  if (type === undefined || isStruct(type)) {
    let length = Object.keys(value).length;
    return BaseType.DynamicRecord({}, { maxEntries: length });
  }

  // other types use directly
  return type;
}

/**
 * Gets a provable type from value.constructor, otherwise returns undefined.
 */
function provableTypeOfConstructor<T>(
  value: T
): ProvableHashableType<T> | undefined {
  if (!hasProperty(value, 'constructor')) return undefined;

  // special checks for Field, Bool because their constructor doesn't match the function that wraps it
  if (value instanceof Field) return Field as any;
  if (value instanceof Bool) return Bool as any;

  let constructor = value.constructor;
  if (!ProvableType.isProvableHashableType(constructor)) return undefined;
  return constructor;
}

/**
 * Gets the inner type of an array, asserting that it is unique.
 *
 * Throws an error for inhomogeneous arrays like [1, 'a'].
 * These should be represented as records i.e. { first: 1, second: 'a' }.
 */
function innerArrayType(array: unknown[]): ProvableHashableType {
  let type = provableTypeOf(array[0]);
  assert(
    array.every((v) => provableTypeEquals(v, type)),
    'Array elements must be homogenous'
  );
  return type;
}

function provableTypeEquals(
  value: unknown,
  type: ProvableHashableType
): boolean {
  if (typeof value === 'string') {
    return isSubclass(type, BaseType.DynamicString.Base);
  }
  if (typeof value === 'number') return type === UInt64;
  if (typeof value === 'boolean') return type === Bool;
  if (typeof value === 'bigint') return type === Field;
  if (value === undefined || value === null) return type === Undefined;

  if (Array.isArray(value)) {
    if (!isSubclass(type, BaseType.DynamicArray.Base)) return false;
    let innerType = type.prototype.innerType;
    return value.every((v) => provableTypeEquals(v, innerType));
  }
  // dynamic types only have to be compatible
  if (value instanceof BaseType.DynamicArray.Base)
    return (
      isSubclass(type, BaseType.DynamicArray.Base) &&
      value.maxLength <= type.prototype.maxLength
    );

  let valueType = provableTypeOfConstructor(value);

  // handle structs and unknown objects as dynamic records
  if (
    valueType === undefined ||
    isStruct(valueType) ||
    value instanceof BaseType.GenericRecord.Base
  ) {
    let length =
      value instanceof BaseType.GenericRecord.Base
        ? value.maxEntries
        : Object.keys(value).length;
    return (
      isSubclass(type, BaseType.GenericRecord.Base) &&
      length <= type.prototype.maxEntries
    );
  }

  // other types check directly
  return valueType === type;
}

// for packing keys -- not compatible with dynamic string hash! (as keys will be known at compile time)
function packStringToField(string: string) {
  let bytes = enc.encode(string);
  let B = Bytes(bytes.length);
  let fields = toFieldsPacked(B, B.from(bytes));
  if (fields.length === 1) return fields[0]!;
  return Poseidon.hash(fields);
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
