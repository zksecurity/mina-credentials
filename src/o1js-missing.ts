/**
 * This file exports types and functions that actually should be exported from o1js
 */
import {
  Bool,
  Field,
  type InferProvable,
  type InferValue,
  Provable,
  type ProvablePure,
  Struct,
  Undefined,
} from 'o1js';
import { assert, assertHasProperty, hasProperty } from './util.ts';
import type { NestedProvable } from './nested.ts';

export { ProvableType, assertPure, type ProvablePureType, array, mapValue };

const ProvableType = {
  get<A extends WithProvable<any>>(type: A): ToProvable<A> {
    return (
      (typeof type === 'object' || typeof type === 'function') &&
      type !== null &&
      'provable' in type
        ? type.provable
        : type
    ) as ToProvable<A>;
  },

  // TODO o1js should make sure this is possible for _all_ provable types
  fromValue<T>(value: T): ProvableType<T> {
    if (value === undefined) return Undefined as any;
    if (value instanceof Field) return Field as any;
    if (value instanceof Bool) return Bool as any;
    if (Array.isArray(value))
      return array(ProvableType.fromValue(value[0]), value.length) as any;

    assertHasProperty(
      value,
      'constructor',
      'Encountered provable value without a constructor: Cannot obtain provable type.'
    );
    let constructor = value.constructor;
    assertIsProvable(ProvableType.get(constructor));
    return constructor as any;
  },

  synthesize<T>(type_: ProvableType<T>): T {
    let type = ProvableType.get(type_);
    let fields = Array.from({ length: type.sizeInFields() }, () => Field(0));
    return type.fromFields(fields, type.toAuxiliary());
  },

  isProvableType(type: unknown): type is ProvableType {
    let type_ = ProvableType.get(type);
    return hasProperty(type_, 'toFields') && hasProperty(type_, 'fromFields');
  },

  constant<T>(value: T): ProvablePure<T, T> & { serialize(): any } {
    return {
      serialize() {
        return { type: 'Constant', value };
      },
      sizeInFields: () => 0,
      toFields: () => [],
      fromFields: () => value,
      toValue: (v) => v,
      fromValue: (v) => v,
      toAuxiliary: () => [],
      check() {},
    };
  },
};

function assertPure<T>(type_: Provable<T>): asserts type_ is ProvablePure<T>;
function assertPure<T>(
  type: ProvableType<T>
): asserts type is ProvablePureType<T>;
function assertPure<T>(
  type: ProvableType<T>
): asserts type is ProvablePureType<T> {
  let aux = ProvableType.get(type).toAuxiliary();
  assert(
    lengthRecursive(aux) === 0,
    'Expected pure provable type to have no auxiliary fields'
  );
}

type NestedArray = any[] | NestedArray[];

function lengthRecursive(array: NestedArray): number {
  if (!Array.isArray(array)) return 1;
  let length = 0;
  for (let i = 0; i < array.length; i++) {
    length += lengthRecursive(array[i]);
  }
  return length;
}

function assertIsProvable(type: unknown): asserts type is Provable<any> {
  assertHasProperty(
    type,
    'toFields',
    'Expected provable type to have a toFields method'
  );
  assertHasProperty(
    type,
    'fromFields',
    'Expected provable type to have a fromFields method'
  );
}

type WithProvable<A> = { provable: A } | A;
type ProvableType<T = any, V = any> = WithProvable<Provable<T, V>>;
type ProvablePureType<T = any, V = any> = WithProvable<ProvablePure<T, V>>;
type ToProvable<A extends WithProvable<any>> = A extends {
  provable: infer P;
}
  ? P
  : A;

// temporary, until we land `StaticArray`
// this is copied from o1js and then modified: https://github.com/o1-labs/o1js
// License here: https://github.com/o1-labs/o1js/blob/main/LICENSE
function array<A extends NestedProvable>(elementType: A, length: number) {
  type T = InferProvable<A>;
  type V = InferValue<A>;
  let type: Provable<T, V> = ProvableType.isProvableType(elementType)
    ? ProvableType.get(elementType)
    : Struct(elementType);
  return {
    _isArray: true,
    innerType: elementType,
    size: length,

    /**
     * Returns the size of this structure in {@link Field} elements.
     * @returns size of this structure
     */
    sizeInFields() {
      let elementLength = type.sizeInFields();
      return elementLength * length;
    },
    /**
     * Serializes this structure into {@link Field} elements.
     * @returns an array of {@link Field} elements
     */
    toFields(array: T[]) {
      return array.map((e) => type.toFields(e)).flat();
    },
    /**
     * Serializes this structure's auxiliary data.
     * @returns auxiliary data
     */
    toAuxiliary(array?) {
      let array_ = array ?? Array<undefined>(length).fill(undefined);
      return array_?.map((e) => type.toAuxiliary(e));
    },

    /**
     * Deserializes an array of {@link Field} elements into this structure.
     */
    fromFields(fields: Field[], aux?: any[]) {
      let array = [];
      let size = type.sizeInFields();
      let n = length;
      for (let i = 0, offset = 0; i < n; i++, offset += size) {
        array[i] = type.fromFields(
          fields.slice(offset, offset + size),
          aux?.[i]
        );
      }
      return array;
    },
    check(array: T[]) {
      for (let i = 0; i < length; i++) {
        (type as any).check(array[i]);
      }
    },
    toCanonical(x) {
      return x.map((v) => Provable.toCanonical(type, v));
    },

    toValue(x) {
      return x.map((v) => type.toValue(v));
    },

    fromValue(x) {
      return x.map((v) => type.fromValue(v));
    },
  } satisfies Provable<T[], V[]> & {
    _isArray: true;
    innerType: A;
    size: number;
  };
}

// this is copied from o1js and then modified: https://github.com/o1-labs/o1js
// License here: https://github.com/o1-labs/o1js/blob/main/LICENSE
function mapValue<
  A extends ProvablePure<any>,
  V extends InferValue<A>,
  W,
  T extends InferProvable<A>
>(
  provable: A,
  there: (x: V) => W,
  back: (x: W | T) => V | T
): ProvablePure<T, W>;

function mapValue<
  A extends Provable<any>,
  V extends InferValue<A>,
  W,
  T extends InferProvable<A>
>(provable: A, there: (x: V) => W, back: (x: W | T) => V | T): Provable<T, W>;

function mapValue<
  A extends Provable<any>,
  V extends InferValue<A>,
  W,
  T extends InferProvable<A>
>(provable: A, there: (x: V) => W, back: (x: W | T) => V | T): Provable<T, W> {
  return {
    sizeInFields: provable.sizeInFields,
    toFields: provable.toFields,
    toAuxiliary: provable.toAuxiliary,
    fromFields: provable.fromFields,
    check: provable.check,
    toCanonical: provable.toCanonical,

    toValue(value) {
      return there(provable.toValue(value));
    },
    fromValue(value) {
      return provable.fromValue(back(value));
    },
  };
}
