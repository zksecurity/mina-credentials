import { Bytes, Gadgets, Provable, UInt32 } from 'o1js';
import * as nodeAssert from 'node:assert';
import { DynamicSHA256 } from './dynamic-sha256.ts';
import { zip } from '../util.ts';
import { DynamicBytes } from './dynamic-bytes.ts';

const { SHA256 } = Gadgets;

const DynBytes = DynamicBytes({ maxLength: 430 });
const StaticBytes = Bytes(stringLength(longString()));

let bytes = DynBytes.fromString(longString());
let staticBytes = StaticBytes.fromString(longString());

let actualPadding = DynamicSHA256.padding(bytes);
let expectedPadding = SHA256.padding(staticBytes);
nodeAssert.deepStrictEqual(
  actualPadding.toValue().map(blockToHexBytes),
  expectedPadding.map(blockToHexBytes)
);

let actualHash = DynamicSHA256.hash(bytes);
let expectedHash = SHA256.hash(staticBytes);
nodeAssert.deepStrictEqual(actualHash.toBytes(), expectedHash.toBytes());

// in-circuit test

async function circuit() {
  let bytesVar = Provable.witness(DynBytes, () => bytes);
  let hash = DynamicSHA256.hash(bytesVar);

  zip(hash.bytes, expectedHash.bytes).forEach(([a, b], i) => {
    a.assertEquals(b, `hash[${i}]`);
  });
}

async function circuitStatic() {
  let bytesVar = Provable.witness(StaticBytes, () => staticBytes);
  let hash = SHA256.hash(bytesVar);

  zip(hash.bytes, expectedHash.bytes).forEach(([a, b], i) => {
    a.assertEquals(b, `hash[${i}]`);
  });
}

await Provable.runAndCheck(circuit);
await Provable.runAndCheck(circuitStatic);

// constraints

let constraints = await Provable.constraintSystem(circuit);
console.log('dynamic', constraints.summary());

let constraintStatic = await Provable.constraintSystem(circuitStatic);
console.log('static', constraintStatic.summary());

let ratio = constraints.rows / constraintStatic.rows;
console.log(`static # of bytes: ${staticBytes.length}`);
console.log(`max dynamic # of bytes: ${bytes.maxLength}`);
console.log(`static # of blocks: ${expectedPadding.length}`);
console.log(`max dynamic # of blocks: ${actualPadding.maxLength}`);
console.log(
  `constraint overhead for dynamic: ${((ratio - 1) * 100).toFixed(2)}%`
);

// helpers

function toHexBytes(uint32: bigint | UInt32) {
  return UInt32.from(uint32).toBigint().toString(16).padStart(8, '0');
}
function blockToHexBytes(block: (bigint | UInt32)[]) {
  return block.map(toHexBytes);
}

// ~400 bytes, needs 7 blocks, also contains unicode
function longString(): string {
  return `SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the
United States National Security Agency (NSA) and first published in 2001.[3][4]
They are built using the Merkle–Damgård construction, from a one-way compression function itself
built using the Davies–Meyer structure from a specialized block cipher.

SHA-2 includes significant changes from its predecessor, SHA-1.`;
}
function stringLength(s: string) {
  return new TextEncoder().encode(s).length;
}
