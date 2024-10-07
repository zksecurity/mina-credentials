import { Field, Gadgets, Hash, UInt32 } from 'o1js';
import { DynamicBytes } from './dynamic-bytes';

const { SHA256 } = Gadgets;

const Bytes = DynamicBytes({ maxLength: 80 });

let bytes = Bytes.fromString('test');

let { blocks, blocksLength } = createPaddedBlocks(bytes);

let states: UInt32[][] = [];
let state = SHA256.initialState;
states.push(state);

// hash max number of blocks
for (let block of blocks) {
  state = hashBlock(state, block);
  states.push(state);
}

// pick the state after the actual number of blocks
// TODO

/**
 * Apply padding to dynamic-length input bytes and split them into sha2 blocks
 */
function createPaddedBlocks(bytes: DynamicBytes): {
  blocks: UInt32[][];
  blocksLength: Field;
} {
  throw Error('todo');
}

function hashBlock(state: UInt32[], block: UInt32[]) {
  let W = SHA256.createMessageSchedule(block);
  return SHA256.compression(state, W);
}
