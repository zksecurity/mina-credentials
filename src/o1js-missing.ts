/**
 * This file exports types and functions that actually should be exported from o1js
 */
import {
  Bool,
  Field,
  type InferProvable,
  Provable,
  type ProvablePure,
  Undefined,
} from 'o1js';
import { assert, assertHasProperty, hasProperty } from './util.ts';

export {
  ProvableType,
  assertPure,
  type ProvablePureType,
  type InferProvableType,
};

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
  fromValue<T>(value: T): Provable<T> {
    if (value === undefined) return Undefined as any;
    if (value instanceof Field) return Field as any;
    if (value instanceof Bool) return Bool as any;
    assertHasProperty(
      value,
      'constructor',
      'Encountered provable value without a constructor: Cannot obtain provable type.'
    );
    let constructor = value.constructor;
    let type = ProvableType.get(constructor);
    assertIsProvable(type);
    return type;
  },

  synthesize<T>(type_: ProvableType<T>): T {
    let type = ProvableType.get(type_);
    let fields = Array.from({ length: type.sizeInFields() }, (_, i) =>
      Field(0)
    );
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
type InferProvableType<T extends ProvableType> = InferProvable<ToProvable<T>>;
