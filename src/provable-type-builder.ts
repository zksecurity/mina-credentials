/**
 * This is a little library to streamline the creation of new provable types.
 */
import {
  provable,
  type ProvableHashable,
  type InferProvable,
  type InferValue,
} from 'o1js';
import type { NestedProvable } from './nested.ts';
import type { ProvableHashablePure } from './o1js-missing.ts';

export { TypeBuilder, TypeBuilderPure };

class TypeBuilder<T, V> {
  type: ProvableHashable<T, V>;
  constructor(type: ProvableHashable<T, V>) {
    this.type = type;
  }

  static shape<A extends NestedProvable>(
    nested: A
  ): TypeBuilder<InferProvable<A>, InferValue<A>> {
    return new TypeBuilder(provable(nested));
  }

  build(): ProvableHashable<T, V> {
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
      empty() {
        return new Class(type.empty());
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
    distinguish: (x: T | W) => x is T;
  }): TypeBuilder<T, W> {
    let type = this.type;
    return new TypeBuilder({
      ...type,

      toValue(value) {
        return transform.there(type.toValue(value));
      },
      fromValue(value) {
        if (transform.distinguish(value)) return value;
        return type.fromValue(transform.back(value));
      },
    });
  }
}

class TypeBuilderPure<T, V> extends TypeBuilder<T, V> {
  type: ProvableHashablePure<T, V>;

  constructor(type: ProvableHashablePure<T, V>) {
    super(type);
    this.type = type;
  }

  build(): ProvableHashablePure<T, V> {
    return this.type;
  }
  forClass<C extends T>(Class: new (t: T) => C): TypeBuilderPure<C, V> {
    return super.forClass(Class) as TypeBuilderPure<C, V>;
  }
  mapValue<W>(transform: {
    there: (x: V) => W;
    back: (x: W) => V;
    distinguish: (x: T | W) => x is T;
  }): TypeBuilderPure<T, W> {
    return super.mapValue(transform) as TypeBuilderPure<T, W>;
  }
}
