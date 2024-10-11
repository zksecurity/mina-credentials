import { Bytes, Gadgets, Provable, UInt32, UInt8 } from 'o1js';
import { DynamicArray } from './dynamic-array.ts';
import * as nodeAssert from 'node:assert';
import { DynamicSHA256 } from './dynamic-sha256.ts';
import { zip } from '../util.ts';

const { SHA256 } = Gadgets;

class DynamicBytes extends DynamicArray(UInt8, { maxLength: 180 }) {
  static fromString(s: string) {
    return DynamicBytes.from(
      [...new TextEncoder().encode(s)].map((t) => UInt8.from(t))
    );
  }
}

let bytes = DynamicBytes.fromString(longString());

const StaticBytes = Bytes(longString().length);
let staticBytes = StaticBytes.fromString(longString());

nodeAssert.deepStrictEqual(
  DynamicSHA256.padding(bytes).toValue().map(blockToHexBytes),
  SHA256.padding(staticBytes).map(blockToHexBytes)
);

let actualHash = DynamicSHA256.hash(bytes);
let expectedHash = SHA256.hash(staticBytes);
nodeAssert.deepStrictEqual(actualHash.toBytes(), expectedHash.toBytes());

// in-circuit test

async function circuit() {
  let bytesVar = Provable.witness(DynamicBytes, () => bytes);
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

// 170 characters, needs 3 blocks
function longString(): string {
  return `SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the
United States National Security Agency (NSA) and first published in 2001.[3][4]`;
}
