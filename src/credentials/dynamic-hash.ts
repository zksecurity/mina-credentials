/**
 * Hashing of arbitrary data types compatible with dynamic-length schemas.
 */
import { Bytes, Field, Poseidon, Struct } from 'o1js';
import { ProvableType, toFieldsPacked } from '../o1js-missing.ts';
import { assert, hasProperty, mapEntries } from '../util.ts';
import { NestedProvable } from '../nested.ts';
import { GenericRecord, type UnknownRecord } from './dynamic-record.ts';

export { packStringToField, packToField, hashRecord };

// compatible hashing

function packStringToField(string: string) {
  let bytes = new TextEncoder().encode(string);
  let B = Bytes(bytes.length);
  let fields = toFieldsPacked(B, B.from(bytes));
  if (fields.length === 1) return fields[0]!;
  return Poseidon.hash(fields);
}

function packToField<T>(type: ProvableType<T>, value: T): Field {
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

function isStruct(type: ProvableType): type is Struct<any> {
  return hasProperty(type, '_isStruct') && type._isStruct === true;
}
