import { Field, Gadgets, Provable, UInt32, UInt8 } from 'o1js';
import { DynamicArray } from './dynamic-array';
import { assert } from 'console';

const { SHA256 } = Gadgets;

class Bytes extends DynamicArray(UInt8, { maxLength: 80 }) {
  static fromString(s: string) {
    return Bytes.from(
      [...new TextEncoder().encode(s)].map((t) => UInt8.from(t))
    );
  }
}
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
  // sha2 blocks are 64 bytes = 16 uint32s each
  let blocks = bytes.chunk(64).map(State, bytesToState);

  // apply padding:
  // 1. get the last block
  let lastIndex = blocks.length.sub(1);
  let last = blocks.getOrUnconstrained(lastIndex);

  // 2. apply padding and update block again (no-op if there are zero blocks)
  blocks.setOrDoNothing(lastIndex, padLastBlock(last));

  return blocks;
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

function chunk<T>(array: T[], size: number): T[][] {
  assert(array.length % size === 0, 'invalid input length');
  return Array.from({ length: array.length / size }, (_, i) =>
    array.slice(size * i, size * (i + 1))
  );
}
