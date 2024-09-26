export { assert, assertHasProperty };

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
