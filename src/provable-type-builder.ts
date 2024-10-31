/**
 * This is a little library to streamline the creation of new provable types.
 */
import {
  provable,
  type InferProvable,
  type InferValue,
  type Provable,
} from 'o1js';
import { NestedProvable } from './nested';

export { TypeBuilder };

class TypeBuilder<T, V> {
  type: Provable<T, V>;
  constructor(type: Provable<T, V>) {
    this.type = type;
  }

  static shape<A extends NestedProvable>(
    nested: A
  ): TypeBuilder<InferProvable<A>, InferValue<A>> {
    return new TypeBuilder(provable(nested));
  }

  build(): Provable<T, V> {
    return this.type;
  }

  forClass<C extends T>(Class: new (t: T) => C): TypeBuilder<C, V> {
    let type = this.type;
    return new TypeBuilder<C, V>({
      ...type,

      fromFields(fields, aux) {
        return new Class(type.fromFields(fields, aux));
      },
      fromValue(value) {
        return new Class(type.fromValue(value));
      },
      toCanonical(x) {
        if (type.toCanonical === undefined) return x;
        return new Class(type.toCanonical(x));
      },
    });
  }

  mapValue<W>(transform: {
    there: (x: V) => W;
    back: (x: W) => V;
    isT: (x: T | W) => x is T;
  }): TypeBuilder<T, W> {
    let type = this.type;
    return new TypeBuilder({
      ...type,

      toValue(value) {
        return transform.there(type.toValue(value));
      },
      fromValue(value) {
        if (transform.isT(value)) return value;
        return type.fromValue(transform.back(value));
      },
    });
  }
}
