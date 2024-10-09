/**
 * This file exports types and functions that actually should be exported from o1js
 */
import { Field, type InferProvable, Provable, type ProvablePure } from 'o1js';

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

  synthesize<T>(type: ProvableType<T>): T {
    let t = ProvableType.get(type);
    return t.fromFields(
      Array.from({ length: t.sizeInFields() }, () => Field(0)),
      t.toAuxiliary()
    );
  },
};

type WithProvable<A> = { provable: A } | A;
type ProvableType<T = any, V = any> = WithProvable<Provable<T, V>>;
type ProvablePureType<T = any, V = any> = WithProvable<ProvablePure<T, V>>;
type ToProvable<A extends WithProvable<any>> = A extends {
  provable: infer P;
}
  ? P
  : A;
type InferProvableType<T extends ProvableType> = InferProvable<ToProvable<T>>;
