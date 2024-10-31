/**
 * A dynamic record is a key-value list which can contain keys/values you are not aware of at compile time.
 */
import { Field, InferProvable, Poseidon, Provable, Unconstrained } from 'o1js';
import { DynamicString } from './dynamic-string';
import { DynamicArray } from './dynamic-array';
import { array, ProvableType } from '../o1js-missing';
import { TypeBuilder } from '../provable-type-builder';
import { mapObject } from '../util';

export { DynamicRecord };

function DynamicRecord<AKnown extends Record<string, ProvableType>>(
  knownShape: AKnown,
  options: {
    maxEntries: number;
    maxKeyLength: number;
    maxValueLength: number;
  }
) {
  type TKnown = { [K in keyof AKnown]: InferProvable<AKnown[K]> };
  let { maxEntries, maxKeyLength, maxValueLength } = options;
  let Key = DynamicString({ maxLength: maxKeyLength });
  let Value = DynamicArray(Field, { maxLength: maxValueLength });

  class DynamicRecord extends DynamicRecordBase<TKnown> {
    static from<A extends AKnown>(
      type: A,
      value: { [K in keyof A]: InferProvable<A[K]> }
    ): DynamicRecord {
      // TODO: validation that the shape extends the known shape
      let preentries = mapObject(type, (t, key) =>
        ProvableType.get(t).toFields(value[key])
      );
      let entries = Object.entries(preentries).map(([key, value]) => ({
        key: Poseidon.hashPacked(Key, Key.from(key)),
        value: Poseidon.hashPacked(Value, Value.from(value)),
      }));

      throw Error('Not implemented');
    }

    static get provable() {
      return provableR;
    }

    get maxEntries() {
      return maxEntries;
    }
    get maxKeyLength() {
      return maxKeyLength;
    }
    get maxValueLength() {
      return maxValueLength;
    }
  }
  let provableR = provableRecord(options, DynamicRecord);

  return DynamicRecord;
}

class DynamicRecordBase<T extends Record<string, any> = any> {
  entries: { key: Field; value: Field }[];
  actual: Unconstrained<UnknownRecord>;

  constructor(value: DynamicRecordRaw) {
    this.entries = value.entries;
    this.actual = value.actual;
  }

  static get provable(): Provable<DynamicRecordBase, RecordValue> {
    throw Error('Need subclass');
  }

  get maxEntries(): number {
    throw Error('Need subclass');
  }
  get maxKeyLength(): number {
    throw Error('Need subclass');
  }
  get maxValueLength(): number {
    throw Error('Need subclass');
  }

  get<K extends keyof T>(key: K): T[K] {
    throw Error('Not implemented');
  }

  hash(): Field {
    throw Error('Not implemented');
  }
}

type DynamicRecordRaw = {
  entries: { key: Field; value: Field }[];
  actual: Unconstrained<UnknownRecord>;
};
type RecordValue = {
  entries: { key: bigint; value: bigint }[];
  actual: UnknownRecord;
};

type UnknownRecord = Record<string, unknown>;
type FieldRecord = Record<string, Field[]>;
type BigintRecord = Record<string, bigint[]>;

function toFieldRecord<A extends Record<string, ProvableType>>(
  type: A,
  value: { [K in keyof A]: InferProvable<A[K]> }
) {
  return mapObject(type, (t, key) => ProvableType.get(t).toFields(value[key]));
}

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

  return (
    TypeBuilder.shape({
      entries: array({ key: Field, value: Field }, maxEntries),
      actual: Unconstrained.withEmpty<UnknownRecord>({}),
    })
      .forClass(Class)
      // .mapValue<FieldRecord>({
      //   there: ({ actual }) => mapObject(actual, (xs) => xs.map(Field)),
      //   back(value) {
      //     let entries = Object.entries(value).map(([key, value]) => ({
      //       key: Poseidon.hashPacked(Key, Key.from(key)).toBigInt(),
      //       value: Poseidon.hashPacked(Value, Value.from(value)).toBigInt(),
      //     }));
      //     let actual = mapObject(value, (xs) => xs.map((x) => x.toBigInt()));
      //     return { entries, actual };
      //   },
      //   isT: (x): x is C => x instanceof Class,
      // })
      .build()
  );
}
