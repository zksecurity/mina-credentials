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
  S extends Serialized = Serialized,
  V = any
> = {
  typeToJSON(constructor: ReturnType<A>): S;

  typeFromJSON(json: S): ReturnType<A> | undefined;

  valueToJSON(value: InstanceType<ReturnType<A>>): V;

  valueFromJSON(
    type: ReturnType<A>,
    json: V
  ): InstanceType<ReturnType<A>> | undefined;
};

type SerializedFactory = {
  _isFactory: true;
} & Serialized;

type Serialized = {
  _type: string;
} & Record<string, any>;

const factories = new Map<
  string,
  { base: ProvableFactory['Base'] } & Serializer
>();

const ProvableFactory = {
  register<A extends ProvableFactory, S extends Serialized, V>(
    factory: A,
    serialize: Serializer<A, S, V>
  ) {
    assert(!factories.has(factory.name), 'Factory already registered');
    factories.set(factory.name, { base: factory.Base, ...serialize });
  },

  getRegistered(constructor: unknown) {
    for (let factory of factories.values()) {
      if (!hasProperty(constructor, 'prototype')) continue;
      if (constructor.prototype instanceof factory.base) return factory;
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

  getRegisteredValue(value: unknown) {
    for (let factory of factories.values()) {
      if (value instanceof factory.base) return factory;
    }
    return undefined;
  },

  tryValueToJSON(value: unknown): (Serialized & { value: any }) | undefined {
    let factory = ProvableFactory.getRegisteredValue(value);
    if (factory === undefined) return undefined;
    console.log('factory', factory);
    let serializedType = factory.typeToJSON(value!.constructor as any);
    return {
      _isFactory: true as const,
      ...serializedType,
      value: factory.valueToJSON(value),
    };
  },

  isSerialized(json: unknown): json is SerializedFactory {
    return hasProperty(json, '_isFactory') && json._isFactory === true;
  },

  fromJSON(json: SerializedFactory): Constructor & ProvableType {
    let factory = factories.get(json._type);
    assert(factory !== undefined, `Type '${json._type}' not registered`);

    let serialized = factory.typeFromJSON(json);
    assert(
      serialized !== undefined,
      `Invalid serialization of type '${json._type}'`
    );
    return serialized;
  },

  valueFromJSON(json: Serialized & { value: any }): any {
    console.log('json', json);
    let factory = factories.get(json._type);
    assert(factory !== undefined, `Type '${json._type}' not registered`);

    let type = factory.typeFromJSON(json);
    assert(type !== undefined, `Invalid serialization of type '${json._type}'`);
    return factory.valueFromJSON(type, json.value);
  },
};
