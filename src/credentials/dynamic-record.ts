/**
 * A dynamic record is a key-value list which can contain keys/values you are not aware of at compile time.
 */
import { Field, Poseidon, Unconstrained } from 'o1js';
import { DynamicString } from './dynamic-string';
import { DynamicArray } from './dynamic-array';
import { array } from '../o1js-missing';
import { TypeBuilder } from '../provable-type-builder';

class DynamicRecordBase<T extends Record<string, any> = any> {
  entries: { key: Field; value: Field }[];
  actual: Unconstrained<RecordValue>;

  constructor(value: DynamicRecordRaw) {
    this.entries = value.entries;
    this.actual = value.actual;
  }
}

type DynamicRecordRaw = {
  entries: { key: Field; value: Field }[];
  actual: Unconstrained<Record<string, bigint[]>>;
};
type RecordValue = Record<string, bigint[]>;

function provableRecord<C extends DynamicRecordBase>(
  options: {
    maxEntries: number;
    maxKeyLength: number;
    maxValueLength: number;
  },
  Class: new (value: DynamicRecordRaw) => C
) {
  let { maxEntries, maxKeyLength, maxValueLength } = options;
  let Key = DynamicString({ maxLength: maxKeyLength });
  let Value = DynamicArray(Field, { maxLength: maxValueLength });

  return TypeBuilder.fromShape({
    entries: array({ key: Field, value: Field }, maxEntries),
    actual: Unconstrained.withEmpty<RecordValue>({}),
  })
    .forClass(Class)
    .mapValue({
      there: ({ actual }) => actual,
      back(actual) {
        let entries = Object.entries(actual).map(([key, value]) => ({
          key: Poseidon.hashPacked(Key, Key.from(key)).toBigInt(),
          value: Poseidon.hashPacked(Value, Value.from(value)).toBigInt(),
        }));
        return { entries, actual };
      },
      isT: (x): x is C => x instanceof Class,
    })
    .build();
}
