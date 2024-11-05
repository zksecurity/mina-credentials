/**
 * This file is just a hack to break import cycles
 */
import type { DynamicArray } from './dynamic-array.ts';
import type { DynamicString } from './dynamic-string.ts';
import type { DynamicRecord, GenericRecord } from './dynamic-record.ts';
import { assertDefined } from '../util.ts';

export { BaseType };

let baseType: {
  DynamicArray?: typeof DynamicArray;
  DynamicString?: typeof DynamicString;
  DynamicRecord?: typeof DynamicRecord;
  GenericRecord?: typeof GenericRecord;
} = {};
type BaseType = typeof baseType;

const BaseType = {
  set<K extends keyof BaseType>(key: K, value: BaseType[K]) {
    baseType[key] = value;
  },
  get DynamicArray() {
    assertDefined(baseType.DynamicArray);
    return baseType.DynamicArray;
  },
  get DynamicString() {
    assertDefined(baseType.DynamicString);
    return baseType.DynamicString;
  },
  get DynamicRecord() {
    assertDefined(baseType.DynamicRecord);
    return baseType.DynamicRecord;
  },
  get GenericRecord() {
    assertDefined(baseType.GenericRecord);
    return baseType.GenericRecord;
  },
};
