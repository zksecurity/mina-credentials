import * as fs from 'fs';
import { Field, UInt64 } from 'o1js';
import * as path from 'path';
import { CREDENTIAL_EXPIRY } from './config.ts';

export { Nullifier };

let FILE_PATH = path.join(import.meta.dirname, 'data.json');

type Entry = { nullifier: string; expiresAt: number };

let inMemoryData = loadData();

function loadData(): Entry[] {
  if (!fs.existsSync(FILE_PATH)) return [];

  let data = fs.readFileSync(FILE_PATH, 'utf-8');
  return JSON.parse(data);
}

function saveData(data: Entry[]) {
  fs.writeFileSync(FILE_PATH, JSON.stringify(data), 'utf-8');
}

function add(nullifier: Field) {
  // expiry date is an upper bound: credentials are only valid for 1 year, so nullifiers
  // created from them don't need to be stored longer than that
  // (it doesn't matter if they are stored slightly longer than necessary)
  let expiresAt = Date.now() + CREDENTIAL_EXPIRY;

  let entry = { nullifier: nullifier.toString(), expiresAt };
  inMemoryData.push(entry);
  saveData(inMemoryData);
}

function exists(nullifier: Field): boolean {
  let nullifierStr = nullifier.toString();
  return inMemoryData.some((item) => item.nullifier === nullifierStr);
}

let day = 24 * 60 * 60 * 1000;

// prune nullifiers that have been expired for > 5 days
function prune() {
  let now = Date.now();
  inMemoryData = inMemoryData.filter((item) => item.expiresAt + 5 * day > now);
  saveData(inMemoryData);
}

// prune every 24 hours
setInterval(prune, day);

const Nullifier = { add, exists };
