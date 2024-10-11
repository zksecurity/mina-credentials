import { Bytes, Field, Gadgets, Packed, Provable, UInt32, UInt8 } from 'o1js';
import { DynamicArray } from './dynamic-array.ts';
import { StaticArray } from './static-array.ts';
import { assert, chunk, pad } from '../util.ts';
import * as nodeAssert from 'node:assert';

const { SHA256 } = Gadgets;

class DynamicBytes extends DynamicArray(UInt8, { maxLength: 500 }) {
  static fromString(s: string) {
    return DynamicBytes.from(
      [...new TextEncoder().encode(s)].map((t) => UInt8.from(t))
    );
  }
}
// hierarchy of packed types to do make array ops more efficient
class UInt8x64 extends StaticArray(UInt8, 64) {}
class Block extends StaticArray(UInt32, 16) {}
class UInt32x4 extends StaticArray(UInt32, 4) {}
class UInt128 extends Packed.create(UInt32x4) {}
class UInt128x4 extends StaticArray(UInt128, 4) {}

class State extends StaticArray(UInt32, 8) {}

let bytes = DynamicBytes.fromString(longString());
let blocks = padding(bytes);
let state = blocks.reduce(State, State.from(SHA256.initialState), hashBlock);

const StateBytes = Bytes(32);
let result = StateBytes.from(
  state.array.flatMap((x) => uint32ToBytesBE(x).array)
);

let staticBytes = Bytes.fromString(longString());
nodeAssert.deepStrictEqual(
  blocks.toValue().map(blockToHexBytes),
  SHA256.padding(staticBytes).map(blockToHexBytes)
);
nodeAssert.deepStrictEqual(
  result.toBytes(),
  SHA256.hash(staticBytes).toBytes()
);

/**
 * Apply padding to dynamic-length input bytes and convert them to 64-byte blocks
 */
function padding(message: DynamicArray<UInt8>) {
  /* padded message looks like this:
  
  M ... M 0x1 0x0 ... 0x0 L L L L L L L L

  where
  - M is the original message
  - the 8 L bytes encode the length of the original message, as a uint64
  - padding always starts with a 0x1 byte
  - there are k 0x0 bytes, where k is the smallest number such that
    the padded length (in bytes) is a multiple of 64

  Corollaries:
  - the entire L section is always contained at the end of the last block
  - the 0x1 byte might be in the last block or the one before that
  - max number of blocks = ceil((M.maxLength + 9) / 64) 
  - number of actual blocks = ceil((M.length + 9) / 64) = floor((M.length + 9 + 63) / 64) = floor((M.length + 8) / 64) + 1
  - block number of L section = floor((M.length + 8) / 64)
  - block number of 0x1 byte index = floor(M.length / 64)
  */

  // create blocks of 64 bytes each
  const maxBlocks = Math.ceil((message.maxLength + 9) / 64);
  const BlocksOfBytes = DynamicArray(UInt8x64, { maxLength: maxBlocks });

  let lastBlockIndex = UInt32.Unsafe.fromField(message.length.add(8)).div(64);
  let numberOfBlocks = lastBlockIndex.value.add(1);
  let padded = pad(message.array, maxBlocks * 64, UInt8.from(0));
  let chunked = chunk(padded, 64).map(UInt8x64.from);
  let blocksOfBytes = new BlocksOfBytes(chunked, numberOfBlocks);

  // pack each block of 64 bytes into 16 uint32s (4 bytes each)
  let blocksOfUInt32 = blocksOfBytes.map(Block, (block) =>
    block.chunk(4).map(UInt32, uint32FromBytesBE)
  );

  // pack each block of 16 uint32s into 4 uint128s (4 uint32s each)
  let blocksOfUInt128 = blocksOfUInt32.map(UInt128x4, (block) =>
    block.chunk(4).map(UInt128, UInt128.pack)
  );

  // splice the length in the same way
  // length = l0 + 4*l1 + 16*l2 + 64*l3
  let [l0, l1, l2, l3] = splitMultiIndex(
    UInt32.Unsafe.fromField(message.length)
  );

  // hierarchically get blocks at `length` and set to 0x1 byte
  let block = blocksOfUInt128.getOrUnconstrained(l3);
  let uint32x4 = block.getOrUnconstrained(l2).unpack();
  let uint8x4 = uint32ToBytesBE(uint32x4.getOrUnconstrained(l1));
  uint8x4.setOrDoNothing(l0, UInt8.from(0x80)); // big-endian encoding of 1
  uint32x4.setOrDoNothing(l1, uint32FromBytesBE(uint8x4));
  block.setOrDoNothing(l2, UInt128.pack(uint32x4));
  blocksOfUInt128.setOrDoNothing(l3, block);

  // set last 64 bits to encoded length (in bits, big-endian encoded)
  // in fact, since we assume the length (in bytes) fits in 16 bits, we only need to set the last uint32
  let lastBlock = blocksOfUInt128.getOrUnconstrained(lastBlockIndex.value);
  let lastUInt128 = lastBlock.get(3).unpack();
  lastUInt128.set(2, UInt32.from(0));
  lastUInt128.set(3, encodeLength(message.length));
  lastBlock.set(3, UInt128.pack(lastUInt128));
  blocksOfUInt128.setOrDoNothing(lastBlockIndex.value, lastBlock);

  // unpack all blocks to UInt32[]
  return blocksOfUInt128.map(Block, (block) =>
    block.array.flatMap((uint128) => uint128.unpack().array)
  );
}

function splitMultiIndex(index: UInt32) {
  let { rest: l0, quotient: l1 } = index.divMod(64);
  let { rest: l00, quotient: l01 } = l0.divMod(16);
  let { rest: l000, quotient: l001 } = l00.divMod(4);
  return [l000.value, l001.value, l01.value, l1.value] as const;
}

function hashBlock(state: State, block: Block): State {
  // console.log('actual: before hashing block', blockToHexBytes(state));
  let W = SHA256.createMessageSchedule(block.array);
  state = State.from(SHA256.compression(state.array, W));
  return state;
}

function uint32FromBytes(bytes: UInt8[] | StaticArray<UInt8>) {
  assert(bytes.length === 4, '4 bytes needed to create a uint32');

  let word = Field(0);
  bytes.forEach(({ value }, i) => {
    word = word.add(value.mul(1n << BigInt(8 * i)));
  });

  return UInt32.Unsafe.fromField(word);
}
function uint32FromBytesBE(bytes: UInt8[] | StaticArray<UInt8>) {
  return uint32FromBytes(bytes.toReversed());
}

function uint32ToBytes(word: UInt32) {
  // witness the bytes
  let bytes = Provable.witness(StaticArray(UInt8, 4), () => {
    let value = word.value.toBigInt();
    return [0, 1, 2, 3].map((i) =>
      UInt8.from((value >> BigInt(8 * i)) & 0xffn)
    );
  });

  // prove that the bytes are correct
  uint32FromBytes(bytes).assertEquals(word);

  return bytes;
}
function uint32ToBytesBE(word: UInt32) {
  return uint32ToBytes(word).toReversed();
}

function encodeLength(lengthInBytes: Field): UInt32 {
  return UInt32.Unsafe.fromField(lengthInBytes.mul(8));
}

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
