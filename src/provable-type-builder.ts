/**
 * This is a little library to streamline the creation of new provable types.
 */
import {
  provable,
  type ProvableHashable,
  type InferProvable,
  type InferValue,
  type IsPure,
  type Field,
} from 'o1js';
import type { NestedProvable } from './nested.ts';
import type { HashInput, ProvableHashablePure } from './o1js-missing.ts';

export { TypeBuilder, TypeBuilderPure };

class TypeBuilder<T, V> {
  type: ProvableHashable<T, V>;

  constructor(type: ProvableHashable<T, V>) {
    this.type = type;
  }

  static shape<A extends NestedProvable>(
    nested: A
  ): IsPure<A, Field> extends true
    ? TypeBuilderPure<InferProvable<A>, InferValue<A>>
    : TypeBuilder<InferProvable<A>, InferValue<A>> {
    return new TypeBuilder(provable(nested)) as any;
  }

  build(): this['type'] {
    return this.type;
  }

  forClass<C extends T>(Class: new (t: T) => C): TypeBuilder<C, V> {
    return this.forConstructor((t) => new Class(t));
  }

  forConstructor<C extends T>(constructor: (t: T) => C): TypeBuilder<C, V> {
    let type = this.type;
    return new TypeBuilder<C, V>({
      ...type,

      fromFields(fields, aux) {
        return constructor(type.fromFields(fields, aux));
      },
      fromValue(value) {
        return constructor(type.fromValue(value));
      },
      empty() {
        return constructor(type.empty());
      },
      toCanonical(x) {
        if (type.toCanonical === undefined) return x;
        return constructor(type.toCanonical(x));
      },
    });
  }

  mapValue<W>(
    transform:
      | {
          there: (x: V) => W;
          back: (x: W) => V;
          distinguish: (x: T | W) => x is T;
        }
      | {
          there: (x: V) => W;
          backAndDistinguish: (x: W | T) => V | T;
        }
  ): TypeBuilder<T, W> {
    let type = this.type;
    return new TypeBuilder({
      ...type,

      toValue(value) {
        return transform.there(type.toValue(value));
      },
      fromValue(value) {
        if ('backAndDistinguish' in transform) {
          return type.fromValue(transform.backAndDistinguish(value));
        }
        if (transform.distinguish(value)) return value;
        return type.fromValue(transform.back(value));
      },
    });
  }

  replaceCheck(check: (x: T) => void) {
    return new TypeBuilder({ ...this.type, check });
  }
  withAdditionalCheck(check: (x: T) => void) {
    let originalCheck = this.type.check;
    return this.replaceCheck((x) => {
      originalCheck(x);
      check(x);
    });
  }

  hashInput(toInput: (x: T) => HashInput): TypeBuilder<T, V> {
    let type = this.type;
    return new TypeBuilder({ ...type, toInput });
  }
}

class TypeBuilderPure<T, V> extends TypeBuilder<T, V> {
  type: ProvableHashablePure<T, V>;

  constructor(type: ProvableHashablePure<T, V>) {
    super(type);
    this.type = type;
  }

  forClass<C extends T>(Class: new (t: T) => C): TypeBuilderPure<C, V> {
    return super.forClass(Class) as TypeBuilderPure<C, V>;
  }
  forConstructor<C extends T>(constructor: (t: T) => C): TypeBuilderPure<C, V> {
    return super.forConstructor(constructor) as TypeBuilderPure<C, V>;
  }

  mapValue<W>(
    transform:
      | {
          there: (x: V) => W;
          back: (x: W) => V;
          distinguish: (x: T | W) => x is T;
        }
      | {
          there: (x: V) => W;
          backAndDistinguish: (x: W | T) => V | T;
        }
  ): TypeBuilderPure<T, W> {
    return super.mapValue(transform) as TypeBuilderPure<T, W>;
  }

  replaceCheck(check: (x: T) => void) {
    return super.replaceCheck(check) as TypeBuilderPure<T, V>;
  }
  withAdditionalCheck(check: (x: T) => void) {
    return super.withAdditionalCheck(check) as TypeBuilderPure<T, V>;
  }
}
