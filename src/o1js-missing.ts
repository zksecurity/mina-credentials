/**
 * This file exports types and functions that actually should be exported from o1js
 */
import { type InferProvable, Provable, type ProvablePure } from 'o1js';
import { assertHasProperty } from './util.ts';

export { ProvableType, type ProvablePureType, type InferProvableType };

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
  fromValue<A>(value: A): Provable<A> {
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
};

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
