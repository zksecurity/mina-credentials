import { Field, Gadgets, UInt32, UInt8 } from 'o1js';
import { DynamicBytes } from './dynamic-bytes';
import { DynamicArray } from './dynamic-array';

const { SHA256 } = Gadgets;

class Bytes extends DynamicArray(UInt8, { maxLength: 80 }) {
  static fromString(s: string) {
    return Bytes.from(
      [...new TextEncoder().encode(s)].map((t) => UInt8.from(t))
    );
  }
}

let bytes = Bytes.fromString('test');

let blocks = createPaddedBlocks(bytes);

let states: UInt32[][] = [];
let state = SHA256.initialState;
states.push(state);

// hash max number of blocks
// for (let block of blocks) {
//   state = hashBlock(state, block);
//   states.push(state);
// }

// pick the state after the actual number of blocks
// TODO

/**
 * Apply padding to dynamic-length input bytes and split them into sha2 blocks
 */
function createPaddedBlocks(
  bytes: DynamicArray<UInt8>
): DynamicArray<UInt32[]> {
  throw Error('todo');
}

function hashBlock(state: UInt32[], block: UInt32[]) {
  let W = SHA256.createMessageSchedule(block);
  return SHA256.compression(state, W);
}
