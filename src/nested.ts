/**
 * Allows us to represent nested Provable types, to save us from always having to
 * wrap types in `Struct` and similar.
 */
import { Provable, type ProvablePure, Struct } from 'o1js';
import { type ProvablePureType, ProvableType } from './o1js-missing.ts';

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

type InferNestedProvable<A> = A extends NestedProvableFor<infer T>
  ? T
  : A extends ProvableType<infer T>
  ? T
  : A extends Record<string, NestedProvable>
  ? {
      [K in keyof A]: InferNestedProvable<A[K]>;
    }
  : never;
