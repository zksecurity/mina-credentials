export { queuePromise };

let lock = Promise.resolve();

async function queuePromise<T>(fn: () => Promise<T>) {
  // acquire the lock
  let existingLock = lock;
  let unlock = () => {};
  lock = new Promise((resolve) => (unlock = resolve));

  // await the existing lock
  await existingLock;

  // run the function and release the lock
  try {
    return await fn();
  } finally {
    unlock();
  }
}
