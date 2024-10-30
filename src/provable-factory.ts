import { ProvableType } from 'o1js';
import { assert, hasProperty } from './util.ts';

export { ProvableFactory, type SerializedFactory };

type Constructor<T = any> = new (...args: any) => T;

/**
 * Standard interface for polymorphic provable type that can be serialized.
 */
type ProvableFactory<N extends string = string, T = any, V = any> = ((
  ...args: any
) => Constructor<T> & ProvableType<T, V>) & {
  name: N;
  Base: Constructor<T>;
};

type Serializer<
  A extends ProvableFactory = ProvableFactory,
  S extends UntaggedSerializedFactory = UntaggedSerializedFactory
> = {
  typeToJSON(constructor: ReturnType<A>): S;

  typeFromJSON(json: S): ReturnType<A> | undefined;
};

type SerializedFactory = {
  _isFactory: true;
} & UntaggedSerializedFactory;

type UntaggedSerializedFactory = {
  _type: string;
} & Record<string, any>;

const factories = new Map<
  string,
  { base: ProvableFactory['Base'] } & Serializer
>();

const ProvableFactory = {
  register<A extends ProvableFactory, S extends UntaggedSerializedFactory>(
    factory: A,
    serialize: Serializer<A, S>
  ) {
    assert(!factories.has(factory.name), 'Factory already registered');
    factories.set(factory.name, { base: factory.Base, ...serialize });
  },

  getRegistered(constructor: unknown) {
    for (let factory of factories.values()) {
      if (!hasProperty(constructor, 'prototype')) continue;
      if (!(constructor.prototype instanceof factory.base)) continue;
      return factory;
    }
    return undefined;
  },

  tryToJSON(constructor: unknown): SerializedFactory | undefined {
    let factory = ProvableFactory.getRegistered(constructor);
    if (factory === undefined) return undefined;

    return Object.assign(factory.typeToJSON(constructor as any), {
      _isFactory: true as const,
    });
  },

  isSerialized(json: unknown): json is SerializedFactory {
    return hasProperty(json, '_isFactory') && json._isFactory === true;
  },

  fromJSON(json: SerializedFactory): Constructor & ProvableType {
    let factory = factories.get(json.type);
    assert(factory !== undefined, 'Factory not registered');

    let serialized = factory.typeFromJSON(json);
    assert(
      serialized !== undefined,
      `Invalid serialization of type '${json.type}'`
    );
    return serialized;
  },
};
