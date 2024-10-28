/**
 * Allows us to represent nested Provable types, to save us from always having to
 * wrap types in `Struct` and similar.
 */
import { type InferProvable, Provable, type ProvablePure, Struct } from 'o1js';
import { array, type ProvablePureType, ProvableType } from './o1js-missing.ts';
import { assertIsObject } from './util.ts';

export { NestedProvable };

export type {
  NestedProvablePure,
  NestedProvableFor,
  NestedProvablePureFor,
  InferNestedProvable,
};

const NestedProvable = {
  get: (<T>(type: NestedProvableFor<T>): Provable<T> => {
    return ProvableType.isProvableType(type)
      ? ProvableType.get(type)
      : Struct(type);
  }) as {
    <T>(type: NestedProvablePureFor<T>): ProvablePure<T>;
    <T>(type: NestedProvableFor<T>): Provable<T>;
    (type: NestedProvablePure): ProvablePure<any>;
    (type: NestedProvable): Provable<any>;
  },

  fromValue<T>(value: T): NestedProvableFor<T> {
    try {
      // case 1: value comes from a provable type
      return ProvableType.fromValue(value);
    } catch {
      // case 2: value is a record of values from provable types
      if (typeof value === 'string') return String as any;

      if (Array.isArray(value))
        return array(NestedProvable.fromValue(value[0]), value.length) as any;

      assertIsObject(value);
      return Object.fromEntries(
        Object.entries(value).map(([key, value]) => [
          key,
          NestedProvable.fromValue(value),
        ])
      ) as any;
    }
  },
};

type NestedProvable = ProvableType | { [key: string]: NestedProvable };
type NestedProvablePure =
  | ProvablePureType
  | { [key: string]: NestedProvablePure };

type NestedProvableFor<T> =
  | ProvableType<T>
  | { [K in keyof T & string]: NestedProvableFor<T[K]> };

type NestedProvablePureFor<T> =
  | ProvablePureType<T>
  | { [K in keyof T & string]: NestedProvablePureFor<T[K]> };

type InferNestedProvable<A> = A extends ProvableType
  ? InferProvable<A>
  : A extends Record<string, NestedProvable>
  ? {
      [K in keyof A]: InferNestedProvable<A[K]>;
    }
  : never;
