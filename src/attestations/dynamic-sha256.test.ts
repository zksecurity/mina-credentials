import { Bytes, Gadgets, UInt32, UInt8 } from 'o1js';
import { DynamicArray } from './dynamic-array.ts';
import { StaticArray } from './static-array.ts';
import * as nodeAssert from 'node:assert';
import { DynamicSHA256 } from './dynamic-sha256.ts';

const { SHA256 } = Gadgets;

class DynamicBytes extends DynamicArray(UInt8, { maxLength: 500 }) {
  static fromString(s: string) {
    return DynamicBytes.from(
      [...new TextEncoder().encode(s)].map((t) => UInt8.from(t))
    );
  }
}

let bytes = DynamicBytes.fromString(longString());
let staticBytes = Bytes.fromString(longString());

nodeAssert.deepStrictEqual(
  DynamicSHA256.padding(bytes).toValue().map(blockToHexBytes),
  SHA256.padding(staticBytes).map(blockToHexBytes)
);
nodeAssert.deepStrictEqual(
  DynamicSHA256.hash(bytes).toBytes(),
  SHA256.hash(staticBytes).toBytes()
);

function toHexBytes(uint32: bigint | UInt32) {
  return UInt32.from(uint32).toBigint().toString(16).padStart(8, '0');
}
function blockToHexBytes(block: (bigint | UInt32)[] | StaticArray<UInt32>) {
  if (Array.isArray(block)) return block.map((uint32) => toHexBytes(uint32));
  return blockToHexBytes((block as StaticArray).array);
}

function longString(): string {
  return `
Symbol.iterator

The Symbol.iterator static data property represents the well-known symbol Symbol.iterator. The iterable protocol looks up this symbol for the method that returns the iterator for an object. In order for an object to be iterable, it must have an [Symbol.iterator] key.  
`;
}
