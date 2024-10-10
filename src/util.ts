export { assert, assertHasProperty, hasProperty, zip, chunk, pad };

function assert(condition: boolean, message?: string): asserts condition {
  if (!condition) {
    throw Error(message ?? 'Assertion failed');
  }
}

function assertHasProperty<K extends string>(
  obj: unknown,
  key: K,
  message?: string
): asserts obj is Record<K, unknown> {
  assert(
    ((typeof obj === 'object' && obj !== null) || typeof obj === 'function') &&
      key in obj,
    message ?? `Expected object to have property ${key}`
  );
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

function chunk<T>(array: T[], size: number): T[][] {
  assert(
    array.length % size === 0,
    `${array.length} is not a multiple of ${size}`
  );
  return Array.from({ length: array.length / size }, (_, i) =>
    array.slice(size * i, size * (i + 1))
  );
}

function pad<T>(array: T[], size: number, value: T): T[] {
  assert(array.length <= size, 'padding array larger than target size');
  return array.concat(Array.from({ length: size - array.length }, () => value));
}
