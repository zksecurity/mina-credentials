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
import {
  assert,
  assertDefined,
  assertExtendsShape,
  assertHasProperty,
  mapEntries,
  mapObject,
  pad,
  zipObjects,
} from '../util.ts';
import { NestedProvable } from '../nested.ts';
import { ProvableFactory } from '../provable-factory.ts';
import {
  deserializeNestedProvable,
  serializeNestedProvable,
  serializeNestedProvableValue,
} from '../serialize-provable.ts';

export {
  DynamicRecord,
  GenericRecord,
  packStringToField,
  packToField,
  hashRecord,
  extractProperty,
};

type GenericRecord = DynamicRecord<{}>;

function GenericRecord(options: { maxEntries: number }) {
  return DynamicRecord({}, options);
}

type DynamicRecord<TKnown = any> = DynamicRecordBase<TKnown>;

function DynamicRecord<
  AKnown extends Record<string, ProvableHashableType>,
  TKnown extends { [K in keyof AKnown]: InferProvable<AKnown[K]> } = {
    [K in keyof AKnown]: InferProvable<AKnown[K]>;
  }
>(knownShape: AKnown, { maxEntries }: { maxEntries: number }) {
  let shape = mapObject<
    AKnown,
    { [K in keyof TKnown]: ProvableHashableType<TKnown[K]> }
  >(knownShape, (type) => type);

  const emptyTKnown: TKnown = mapObject(shape, (type) =>
    ProvableType.get(type).empty()
  );

  TypeBuilder.shape({
    entries: array(Option(Struct({ key: Field, value: Field })), maxEntries),
    actual: Unconstrained.withEmpty<UnknownRecord>(emptyTKnown),
  })
    .build()
    .empty();

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
              key: packStringToField(key).toBigInt(),
              value: packToField(type, value).toBigInt(),
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
    get knownShape() {
      return shape;
    }
  };
}

const OptionField = Option(Field);

class GenericRecordBase {
  entries: Option<{ key: Field; value: Field }>[];
  actual: Unconstrained<UnknownRecord>;

  constructor(value: DynamicRecordRaw) {
    this.entries = value.entries;
    this.actual = value.actual;
  }

  get maxEntries(): number {
    throw Error('Need subclass');
  }

  getAny<A extends ProvableType>(valueType: A, key: string) {
    // find valueHash for key
    let keyHash = packStringToField(key);
    let current = OptionField.none();

    for (let { isSome, value: entry } of this.entries) {
      let isCurrentKey = isSome.and(entry.key.equals(keyHash));
      current.isSome = current.isSome.or(isCurrentKey);
      current.value = Provable.if(isCurrentKey, entry.value, current.value);
    }
    let valueHash = current.assertSome(`Key not found: "${key}"`);

    // witness actual value for key
    let value = Provable.witness(
      valueType,
      () => this.actual.get()[key] as any
    );

    // assert that value matches hash, and return it
    packToField(valueType, value).assertEquals(
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

class DynamicRecordBase<TKnown = any> extends GenericRecordBase {
  get knownShape(): { [K in keyof TKnown]: ProvableHashableType<TKnown[K]> } {
    throw Error('Need subclass');
  }

  get<K extends keyof TKnown & string>(key: K): TKnown[K] {
    let valueType: ProvableHashable<TKnown[K]> = ProvableType.get(
      this.knownShape[key]
    );
    return this.getAny(valueType, key);
  }
}

DynamicRecord.Base = DynamicRecordBase;

type DynamicRecordRaw = {
  entries: Option<{ key: Field; value: Field }>[];
  actual: Unconstrained<UnknownRecord>;
};

type UnknownRecord = Record<string, unknown>;

// compatible hashing

function packStringToField(string: string) {
  let bytes = new TextEncoder().encode(string);
  let B = Bytes(bytes.length);
  let fields = toFieldsPacked(B, B.from(bytes));
  if (fields.length === 1) return fields[0]!;
  return Poseidon.hash(fields);
}

function packToField<T>(type: ProvableType<T>, value: T) {
  let fields = toFieldsPacked(type, value);
  if (fields.length === 1) return fields[0]!;
  return Poseidon.hash(fields);
}

function hashRecord(data: unknown) {
  if (data instanceof DynamicRecord.Base) return data.hash();
  assert(
    typeof data === 'object' && data !== null,
    'Expected DynamicRecord or plain object as data'
  );
  let type: NestedProvable = NestedProvable.fromValue(data);
  assert(!ProvableType.isProvableType(type), 'Expected plain object as data');

  let entryHashes = mapEntries(zipObjects(type, data), (key, [type, value]) => [
    packStringToField(key),
    packToField(NestedProvable.get(type), value),
  ]);
  return Poseidon.hash(entryHashes.flat());
}

// compatible key extraction

function extractProperty(data: unknown, key: string): unknown {
  if (data instanceof DynamicRecord.Base) return data.get(key);
  assertHasProperty(data, key);
  let value = data[key];
  assertDefined(value, `Key not found: "${key}"`);
  return value;
}

// serialize/deserialize

ProvableFactory.register(DynamicRecord, {
  typeToJSON(constructor) {
    return {
      maxEntries: constructor.prototype.maxEntries,
      knownShape: serializeNestedProvable(constructor.prototype.knownShape),
    };
  },

  typeFromJSON(json) {
    let { maxEntries, knownShape } = json;
    let shape = deserializeNestedProvable(knownShape);
    return DynamicRecord(shape as any, { maxEntries });
  },

  valueToJSON(type, value) {
    let actual = type.provable.toValue(value);
    return serializeNestedProvableValue(actual);
  },

  valueFromJSON(type, value) {
    let actual = deserializeNestedProvable(value);
    return type.provable.fromValue(actual);
  },
});
