export {
  assert,
  assertDefined,
  assertHasProperty,
  hasProperty,
  assertIsObject,
  zip,
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

function zip<T, S>(a: T[], b: S[]) {
  assert(a.length === b.length, 'zip(): arrays of unequal length');
  return a.map((a, i): [T, S] => [a, b[i]!]);
}
