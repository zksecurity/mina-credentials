/**
 * This file is just a hack to break import cycles
 */
import type { DynamicArray } from './dynamic-array.ts';
import type { DynamicString } from './dynamic-string.ts';
import type { DynamicRecord, GenericRecord } from './dynamic-record.ts';
import { Required } from '../util.ts';

export { BaseType };

let baseType: {
  DynamicArray?: typeof DynamicArray;
  DynamicString?: typeof DynamicString;
  DynamicRecord?: typeof DynamicRecord;
  GenericRecord?: typeof GenericRecord;
} = {};

const BaseType = Required(baseType);
