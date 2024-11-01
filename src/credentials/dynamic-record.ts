/**
 * A dynamic record is a key-value list which can contain keys/values you are not aware of at compile time.
 */
import {
  Bytes,
  Field,
  From,
  InferProvable,
  Poseidon,
  Unconstrained,
} from 'o1js';
import { array, ProvableHashableType, ProvableType } from '../o1js-missing.ts';
import { TypeBuilder } from '../provable-type-builder.ts';
import { assertExtendsShape, mapObject, zipObjects } from '../util.ts';

export { DynamicRecord, GenericRecord };

type GenericRecord = DynamicRecord<{}>;

function GenericRecord(options: {
  maxEntries: number;
  maxKeyLength: number;
  maxValueLength: number;
}) {
  return DynamicRecord({}, options);
}

type DynamicRecord<TKnown extends Record<string, any>> =
  DynamicRecordBase<TKnown>;

function DynamicRecord<
  AKnown extends Record<string, ProvableHashableType>,
  TKnown extends { [K in keyof AKnown]: InferProvable<AKnown[K]> } = {
    [K in keyof AKnown]: InferProvable<AKnown[K]>;
  }
>(
  knownShape: AKnown,
  options: {
    maxEntries: number;
    maxKeyLength: number;
    maxValueLength: number;
  }
) {
  let { maxEntries, maxKeyLength, maxValueLength } = options;
  // type TKnown = { [K in keyof AKnown]: InferProvable<AKnown[K]> };

  const emptyTKnown: TKnown = mapObject(knownShape, (type) =>
    ProvableType.get(type).empty()
  ) as TKnown;

  return class DynamicRecord extends DynamicRecordBase<TKnown> {
    static from<T extends TKnown>(value: T): DynamicRecordBase<TKnown> {
      return DynamicRecord.provable.fromValue(value);
    }

    static fromShape<A extends AKnown>(
      type: A,
      value: { [K in keyof A]: From<A[K]> }
    ): DynamicRecordBase<TKnown> {
      let actual: { [K in keyof A]: InferProvable<A[K]> } = mapObject(
        zipObjects(type, value),
        ([type, value]) => ProvableType.get(type).fromValue(value)
      );
      return DynamicRecord.provable.fromValue(actual);
    }

    static provable = TypeBuilder.shape({
      entries: array({ key: Field, value: Field }, maxEntries),
      actual: Unconstrained.withEmpty<UnknownRecord>(emptyTKnown),
    })
      .forClass<DynamicRecordBase<TKnown>>(DynamicRecord)
      .mapValue<UnknownRecord>({
        there({ actual }) {
          return actual;
        },
        back(actual) {
          // validate that `actual` (at least) contains all known keys
          assertExtendsShape(actual, knownShape);

          let entries = Object.entries<unknown>(actual).map(([key, value]) => {
            let type = ProvableType.fromValue(value);
            return {
              key: hashString(key).toBigInt(),
              value: Poseidon.hashPacked(type, value).toBigInt(),
            };
          });
          return { entries, actual };
        },
        distinguish(x) {
          return x instanceof DynamicRecord;
        },
      })
      .build();

    get maxEntries() {
      return maxEntries;
    }
    get maxKeyLength() {
      return maxKeyLength;
    }
    get maxValueLength() {
      return maxValueLength;
    }
  };
}

class DynamicRecordBase<TKnown extends Record<string, any> = any> {
  entries: { key: Field; value: Field }[];
  actual: Unconstrained<UnknownRecord>;

  constructor(value: DynamicRecordRaw) {
    this.entries = value.entries;
    this.actual = value.actual;
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

  get<K extends keyof TKnown>(key: K): TKnown[K] {
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

type UnknownRecord = Record<string, unknown>;

// helper

function hashString(string: string) {
  let bytes = new TextEncoder().encode(string);
  let B = Bytes(bytes.length);
  return Poseidon.hashPacked(B, B.from(bytes));
}
