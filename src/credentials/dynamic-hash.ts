/**
 * Hashing of arbitrary data types compatible with dynamic-length schemas.
 */
import { Bytes, Field, Poseidon, Struct, UInt8 } from 'o1js';
import {
  type ProvableHashableType,
  ProvableType,
  toFieldsPacked,
} from '../o1js-missing.ts';
import { assert, hasProperty, mapEntries } from '../util.ts';
import { NestedProvable } from '../nested.ts';
import { GenericRecord, type UnknownRecord } from './dynamic-record.ts';

export {
  hashString,
  packStringToField,
  packToField,
  hashRecord,
  bitSize,
  packedFieldSize,
};

// compatible hashing

const enc = new TextEncoder();

function hashString(string: string) {
  // encode length + bytes
  let bytes = enc.encode(string);
  let length = bytes.length;
  let B = Bytes(length);
  let fields = toFieldsPacked(B, B.from(bytes));
  return Poseidon.hash([Field(length), Field(0), ...fields]);
}

function packStringToField(string: string) {
  let bytes = enc.encode(string);
  let B = Bytes(bytes.length);
  let fields = toFieldsPacked(B, B.from(bytes));
  if (fields.length === 1) return fields[0]!;
  return Poseidon.hash(fields);
}

function packToField<T>(type: ProvableType<T> | undefined, value: T): Field {
  type ??= NestedProvable.get(NestedProvable.fromValue(value));

  // identify "record" types
  if (isStruct(type) || value instanceof GenericRecord.Base) {
    return hashRecord(value);
  }
  let fields = toFieldsPacked(type, value);
  if (fields.length === 1) return fields[0]!;
  return Poseidon.hash(fields);
}

function hashRecord(data: unknown) {
  if (data instanceof GenericRecord.Base) return data.hash();
  assert(
    typeof data === 'object' && data !== null,
    'Expected DynamicRecord or plain object as data'
  );
  let entryHashes = mapEntries(data as UnknownRecord, (key, value) => {
    let type = NestedProvable.get(NestedProvable.fromValue(value));
    return [packStringToField(key), packToField(type, value)];
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
