import { Field, Gadgets, Packed, Provable, UInt32, UInt8 } from 'o1js';
import { DynamicArray } from './dynamic-array.ts';
import { StaticArray } from './static-array.ts';
import { assert, chunk } from '../util.ts';

const { SHA256 } = Gadgets;

class Bytes extends DynamicArray(UInt8, { maxLength: 80 }) {
  static fromString(s: string) {
    return Bytes.from(
      [...new TextEncoder().encode(s)].map((t) => UInt8.from(t))
    );
  }
}
// hierarchy of packed types to do make array ops more efficient
const UInt8x2 = StaticArray(UInt8, 2);
const UInt16 = Packed.create(UInt8x2);
const UInt16x8 = StaticArray(UInt16, 8);
const UInt128 = Packed.create(UInt16x8);
const UInt128x4 = StaticArray(UInt128, 4);
const State = Provable.Array(UInt32, 16);

let bytes = Bytes.fromString('test');

let blocks = createPaddedBlocks(bytes);

let state = blocks.reduce(State, SHA256.initialState, hashBlock);

/**
 * Apply padding to dynamic-length input bytes and split them into sha2 blocks
 */
function createPaddedBlocks(
  bytes: DynamicArray<UInt8>
): DynamicArray<UInt32[]> {
  /* padded message looks like this:
  
  M ... M 0x1 0x0 ... 0x0 L L L L L L L L

  where
  - M is the original message
  - the 8 L bytes encode the length of the original message, as a uint64
  - padding always starts with a 0x1 byte
  - there are k 0x0 bytes, where k is the smallest number such that
    the padded length (in bytes) is a multiple of 64

  Corollary: the entire padding is always contained in the same (last) block
  */

  // create chunks of 64 bytes each
  let { chunks: blocksOfUInt8, innerLength } = bytes.chunk(64);

  // pack each block of 64 bytes into 32 uint16s
  let blocksOfUInt16 = blocksOfUInt8.map(UInt16x8, (block) =>
    UInt16x8.from(chunk(block.array, 2).map(UInt8x2.from).map(UInt16.pack))
  );

  // pack each block of 32 uint16s into 4 uint128s
  let blocksOfUInt128 = blocksOfUInt16.map(UInt128x4, (block) =>
    UInt128x4.from(chunk(block.array, 8).map(UInt16x8.from).map(UInt128.pack))
  );

  throw Error('todo');

  // // apply padding:
  // // 1. get the last block
  // let lastIndex = blocksOfBytes.length.sub(1);
  // let last = blocksOfBytes.getOrUnconstrained(lastIndex);

  // // 2. apply padding and update block again (no-op if there are zero blocks)
  // blocksOfBytes.setOrDoNothing(lastIndex, padLastBlock(last));

  // return blocksOfBytes;
}

function padLastBlock(lastBlock: UInt32[]): UInt32[] {
  throw Error('todo');
}

function hashBlock(state: UInt32[], block: UInt32[]) {
  let W = SHA256.createMessageSchedule(block);
  return SHA256.compression(state, W);
}

function bytesToState(bytes: UInt8[]) {
  assert(bytes.length === 64, '64 bytes needed to create 16 uint32s');
  return chunk(bytes, 4).map(bytesToWord);
}

function bytesToWord(bytes: UInt8[]) {
  assert(bytes.length === 4, '4 bytes needed to create a uint32');

  let word = Field(0);
  bytes.forEach(({ value }, i) => {
    word = word.add(value.mul(1n << BigInt(8 * i)));
  });

  return UInt32.Unsafe.fromField(word);
}
