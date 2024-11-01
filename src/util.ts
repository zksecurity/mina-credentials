export {
  assert,
  assertDefined,
  assertHasProperty,
  hasProperty,
  assertIsObject,
  notImplemented,
  zip,
  chunk,
  pad,
  mapObject,
  zipObjects,
  assertExtendsShape,
};

function assert(condition: boolean, message?: string): asserts condition {
  if (!condition) {
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

function assertIsObject(
  obj: unknown,
  message?: string
): asserts obj is object | Function {
  assert(
    (typeof obj === 'object' && obj !== null) || typeof obj === 'function',
    message
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

function assertExtendsShape<B extends Record<string, any>>(
  a: object,
  b: B
): asserts a is Record<keyof B, any> {
  for (let key in b) {
    if (!(key in a)) throw Error(`Expected object to have property ${key}`);
  }
}
