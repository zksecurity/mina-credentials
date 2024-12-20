import { Field } from 'o1js';
import { CREDENTIAL_EXPIRY } from './config.ts';
import { createJsonStore } from './json-store.ts';

export { Nullifier };

type Entry = { nullifier: string; expiresAt: number };

const store = createJsonStore<Entry[]>('nullifier.json', []);

function add(nullifier: Field) {
  // expiry date is an upper bound: credentials are only valid for 1 year, so nullifiers
  // created from them don't need to be stored longer than that
  // (it doesn't matter if they are stored slightly longer than necessary)
  let expiresAt = Date.now() + CREDENTIAL_EXPIRY;

  let entry = { nullifier: nullifier.toString(), expiresAt };

  let entries = store.get();
  entries.push(entry);
  store.set(entries);
}

function exists(nullifier: Field): boolean {
  let nullifierStr = nullifier.toString();
  let entries = store.get();
  return entries.some((item) => item.nullifier === nullifierStr);
}

let day = 24 * 60 * 60 * 1000;

// prune nullifiers that have been expired for > 5 days
function prune() {
  let now = Date.now();
  let entries = store.get();
  entries = entries.filter((item) => item.expiresAt + 5 * day > now);
  store.set(entries);
}

// prune every 24 hours
setInterval(prune, day);

const Nullifier = { add, exists };
