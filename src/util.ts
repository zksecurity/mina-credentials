export {
  assert,
  assertDefined,
  defined,
  assertHasProperty,
  hasProperty,
  assertIsObject,
  notImplemented,
  zip,
  chunk,
  pad,
  fill,
  mapObject,
  mapEntries,
  zipObjects,
  assertExtendsShape,
  isSubclass,
  stringLength,
};

function assert(
  condition: boolean,
  message?: string | (() => string | undefined)
): asserts condition {
  if (!condition) {
    message = typeof message === 'function' ? message() : message;
    throw Error(message ?? 'Assertion failed');
  }
}

function assertDefined<T>(
  input: T | undefined,
  message?: string
): asserts input is T {
  if (input === undefined) {
    throw Error(message ?? 'Input is undefined');
  }
}

function defined<T>(input: T | undefined, message?: string): T {
  assertDefined(input, message);
  return input;
}

function assertIsObject(
  obj: unknown,
  message?: string
): asserts obj is object | Function {
  assert(
    (typeof obj === 'object' && obj !== null) || typeof obj === 'function',
    () => {
      // console.log('not an object:', obj);
      return message;
    }
  );
}

function assertHasProperty<K extends string>(
  obj: unknown,
  key: K,
  message?: string
): asserts obj is Record<K, unknown> {
  assertIsObject(obj, message ?? `Expected value to be an object or function`);
  assert(key in obj, message ?? `Expected object to have property ${key}`);
}

function hasProperty<K extends string>(
  obj: unknown,
  key: K
): obj is Record<K, unknown> {
  return (
    ((typeof obj === 'object' && obj !== null) || typeof obj === 'function') &&
    key in obj
  );
}

function notImplemented(): never {
  throw Error('Not implemented');
}

function zip<T, S>(a: T[], b: S[]) {
  assert(a.length === b.length, 'zip(): arrays of unequal length');
  return a.map((a, i): [T, S] => [a, b[i]!]);
}

function chunk<T>(array: T[], size: number): T[][] {
  assert(
    array.length % size === 0,
    `${array.length} is not a multiple of ${size}`
  );
  return Array.from({ length: array.length / size }, (_, i) =>
    array.slice(size * i, size * (i + 1))
  );
}

function pad<T>(array: T[], size: number, value: T | (() => T)): T[] {
  assert(
    array.length <= size,
    `padding array of size ${array.length} larger than target size ${size}`
  );
  let cb: () => T =
    typeof value === 'function' ? (value as () => T) : () => value;
  return array.concat(Array.from({ length: size - array.length }, cb));
}

function fill<T>(size: number, value: T | (() => T)): T[] {
  let cb: () => T =
    typeof value === 'function' ? (value as () => T) : () => value;
  return Array.from({ length: size }, cb);
}

function mapObject<
  T extends Record<string, any>,
  S extends Record<keyof T, any>
>(obj: T, fn: <K extends keyof T>(value: T[K], key: K) => S[K]): S {
  let result = {} as S;
  for (let key in obj) {
    result[key] = fn(obj[key], key);
  }
  return result;
}

function zipObjects<
  T extends Record<string, any>,
  S extends Record<keyof T, any>
>(t: T, s: S) {
  assertExtendsShape(t, s);
  assertExtendsShape(s, t);
  return mapObject<T, { [K in keyof T]: [T[K], S[K]] }>(t, (t, key) => [
    t,
    s[key],
  ]);
}

function mapEntries<T extends Record<string, any>, S>(
  obj: T,
  fn: (key: keyof T & string, value: T[keyof T & string]) => S
): S[] {
  return Object.entries(obj).map((entry) => fn(...entry));
}

function assertExtendsShape<B extends Record<string, any>>(
  a: object,
  b: B
): asserts a is Record<keyof B, any> {
  for (let key in b) {
    if (!(key in a)) throw Error(`Expected object to have property ${key}`);
  }
}

type Constructor<T> = new (...args: any) => T;

function isSubclass<B extends Constructor<any>>(
  constructor: unknown,
  base: B
): constructor is B {
  if (typeof constructor !== 'function') return false;
  if (!hasProperty(constructor, 'prototype')) return false;
  return constructor.prototype instanceof base;
}

let enc = new TextEncoder();

function stringLength(str: string): number {
  return enc.encode(str).length;
}
