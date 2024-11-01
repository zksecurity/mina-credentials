/**
 * A dynamic record is a key-value list which can contain keys/values you are not aware of at compile time.
 */
import {
  Bytes,
  Field,
  type From,
  type InferProvable,
  Option,
  Poseidon,
  Provable,
  type ProvableHashable,
  Struct,
  Unconstrained,
} from 'o1js';
import {
  array,
  ProvableType,
  toFieldsPacked,
  type ProvableHashableType,
} from '../o1js-missing.ts';
import { TypeBuilder } from '../provable-type-builder.ts';
import { assertExtendsShape, mapObject, pad, zipObjects } from '../util.ts';
import { NestedProvable } from '../nested.ts';

export { DynamicRecord, GenericRecord, hashString, hashPacked };

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
  let shape = mapObject<
    AKnown,
    { [K in keyof TKnown]: ProvableHashable<TKnown[K]> }
  >(knownShape, (type) => ProvableType.get(type));

  const emptyTKnown: TKnown = mapObject(shape, (type) => type.empty());

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
      entries: array(Option(Struct({ key: Field, value: Field })), maxEntries),
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
            let type = NestedProvable.get(NestedProvable.fromValue(value));
            return {
              key: hashString(key).toBigInt(),
              value: hashPacked(type, value).toBigInt(),
            };
          });
          return { entries: pad(entries, maxEntries, undefined), actual };
        },
        distinguish(x) {
          return x instanceof DynamicRecordBase;
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
    get knownShape() {
      return shape;
    }
  };
}

const OptionField = Option(Field);

class DynamicRecordBase<TKnown extends Record<string, any> = any> {
  entries: Option<{ key: Field; value: Field }>[];
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
  get knownShape(): { [K in keyof TKnown]: ProvableHashable<TKnown[K]> } {
    throw Error('Need subclass');
  }

  get<K extends keyof TKnown & string>(key: K): TKnown[K] {
    // find valueHash for key
    let keyHash = hashString(key);
    let current = OptionField.none();

    for (let { isSome, value: entry } of this.entries) {
      let isCurrentKey = isSome.and(entry.key.equals(keyHash));
      current.isSome = current.isSome.or(isCurrentKey);
      current.value = Provable.if(isCurrentKey, entry.value, current.value);
    }
    let valueHash = current.assertSome(`Key not found: "${key}"`);

    // witness actual value for key
    let valueType: ProvableHashable<TKnown[K]> = this.knownShape[key];
    let value = Provable.witness(valueType, () => this.actual.get()[key]);

    // assert that value matches hash, and return it
    hashPacked(valueType, value).assertEquals(
      valueHash,
      `Bug: Invalid value for key "${key}"`
    );

    return value;
  }

  hash(): Field {
    // hash one entry at a time, ignoring dummy entries
    let state = Poseidon.initialState();

    for (let { isSome, value: entry } of this.entries) {
      let { key, value } = entry;
      let newState = Poseidon.update(state, [key, value]);
      state[0] = Provable.if(isSome, newState[0], state[0]);
      state[1] = Provable.if(isSome, newState[1], state[1]);
      state[2] = Provable.if(isSome, newState[2], state[2]);
    }

    return state[0];
  }
}

type DynamicRecordRaw = {
  entries: Option<{ key: Field; value: Field }>[];
  actual: Unconstrained<UnknownRecord>;
};

type UnknownRecord = Record<string, unknown>;

// helper

function hashString(string: string) {
  let bytes = new TextEncoder().encode(string);
  let B = Bytes(bytes.length);
  return Poseidon.hashPacked(B, B.from(bytes));
}

function hashPacked<T>(type: Provable<T>, value: T) {
  let fields = toFieldsPacked(type, value);
  return Poseidon.hash(fields);
}
