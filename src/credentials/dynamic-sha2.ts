import { Bytes, Provable, UInt32, UInt64, UInt8 } from 'o1js';
import { DynamicArray } from './dynamic-array.ts';
import { StaticArray } from './static-array.ts';
import { chunk, pad } from '../util.ts';
import { SHA2 } from './sha2.ts';
import { uint64FromBytesBE, uint64ToBytesBE } from './gadgets.ts';

export { DynamicSHA2, sha2, padding256, padding512 };

const DynamicSHA2 = {
  /**
   * Hash a dynamic-length byte array using different variants of SHA2.
   *
   * The first argument is the output length in bits (224, 256, 384, or 512).
   *
   * The input type `DynamicArray<UInt8>` is compatible with both `DynamicString` and `DynamicBytes`:
   *
   * ```ts
   * // using DynamicString
   * const String = DynamicString({ maxLength: 120 });
   * let string = String.from('hello');
   * let hash = DynamicSHA2.hash(256, string);
   *
   * // using DynamicBytes
   * const Bytes = DynamicBytes({ maxLength: 120 });
   * let bytes = Bytes.fromHex('010203');
   * let hash = DynamicSHA2.hash(256, bytes);
   * ```
   */
  hash: sha2,

  padding256,
  padding512,
};

function sha2(len: 224 | 256 | 384 | 512, bytes: DynamicArray<UInt8>): Bytes {
  if (len === 224 || len === 256) return hash256(len, bytes);
  if (len === 384 || len === 512) return hash512(len, bytes);
  throw new Error('unsupported hash length');
}

// static array types for blocks / state / result
class UInt8x4 extends StaticArray(UInt8, 4) {}
class UInt8x8 extends StaticArray(UInt8, 8) {}
class UInt8x64 extends StaticArray(UInt8, 64) {}
class UInt8x128 extends StaticArray(UInt8, 128) {}
class Block extends StaticArray(UInt32, 16) {}
class State extends StaticArray(UInt32, 8) {}
class Block64 extends StaticArray(UInt64, 16) {}
class State64 extends StaticArray(UInt64, 8) {}
const Bytes28 = Bytes(28);
const Bytes32 = Bytes(32);
const Bytes48 = Bytes(48);
const Bytes64 = Bytes(64);

function hash256(len: 224 | 256, bytes: DynamicArray<UInt8>): Bytes {
  let blocks = padding256(bytes);

  // hash a dynamic number of blocks using DynamicArray.reduce()
  let state = blocks.reduce(
    State,
    State.from(SHA2.initialState256(len)),
    (state, block) => {
      let W = SHA2.messageSchedule256(block.array);
      return State.from(SHA2.compression256(state.array, W));
    }
  );

  if (len === 224) state = state.slice(0, 7);
  let result = state.array.flatMap((x) => x.toBytesBE());
  return len === 224 ? Bytes28.from(result) : Bytes32.from(result);
}

function hash512(len: 384 | 512, bytes: DynamicArray<UInt8>): Bytes {
  let blocks = padding512(bytes);

  // hash a dynamic number of blocks using DynamicArray.reduce()
  let state = blocks.reduce(
    State64,
    State64.from(SHA2.initialState512(len)),
    (state, block) => {
      let W = SHA2.messageSchedule512(block.array);
      return State64.from(SHA2.compression512(state.array, W));
    }
  );

  if (len === 384) state = state.slice(0, 6);
  let result = state.array.flatMap((x) => uint64ToBytesBE(x));
  return len === 384 ? Bytes48.from(result) : Bytes64.from(result);
}

/**
 * Apply padding to dynamic-length input bytes and convert them to (a dynamic number of) blocks of 16 uint32s.
 */
function padding256(
  message: DynamicArray<UInt8>
): DynamicArray<StaticArray<UInt32>> {
  /* padded message looks like this:
  
  M ... M 0x80 0x0 ... 0x0 L L L L L L L L

  where
  - M is the original message
  - the 8 L bytes encode the length of the original message, as a uint64
  - padding always starts with a 0x80 byte (= big-endian encoding of 1)
  - there are k 0x0 bytes, where k is the smallest number such that
    the padded length (in bytes) is a multiple of 64

  Corollaries:
  - the entire L section is always contained at the end of the last block
  - the 0x80 byte might be in the last block or the one before that
  - max number of blocks = ceil((M.maxLength + 9) / 64) 
  - number of actual blocks = ceil((M.length + 9) / 64) = floor((M.length + 9 + 63) / 64) = floor((M.length + 8) / 64) + 1
  - block number of L section = floor((M.length + 8) / 64)
  - block number of 0x80 byte index = floor(M.length / 64)
  */

  // check that all message bytes beyond the actual length are 0, so that we get valid padding just by adding the 0x80 and L bytes
  // this step creates most of the constraint overhead of dynamic sha2, but seems unavoidable :/
  message.forEach((byte, isPadding) => {
    Provable.assertEqualIf(isPadding, UInt8, byte, UInt8.from(0));
  });

  // create blocks of 64 bytes each
  const maxBlocks = Math.ceil((message.maxLength + 9) / 64);
  const BlocksOfBytes = DynamicArray(UInt8x64, { maxLength: maxBlocks });

  let lastBlockIndex = UInt32.Unsafe.fromField(message.length.add(8)).div(64);
  let numberOfBlocks = lastBlockIndex.value.add(1);
  let padded = pad(message.array, maxBlocks * 64, UInt8.from(0));
  let chunked = chunk(padded, 64).map(UInt8x64.from);
  let blocksOfBytes = new BlocksOfBytes(chunked, numberOfBlocks);

  // pack each block of 64 bytes into 16 uint32s (4 bytes each)
  let blocks = blocksOfBytes.map(Block, (block) =>
    block.chunk(4).map(UInt32, (b) => UInt32.fromBytesBE(b.array))
  );

  // splice the length in the same way
  // length = l0 + 4*l1 + 64*l2
  // so that l2 is the block index, l1 the uint32 index in the block, and l0 the byte index in the uint32
  let [l0, l1, l2] = splitMultiIndex(UInt32.Unsafe.fromField(message.length));

  // hierarchically get byte at `length` and set to 0x80
  // we can use unsafe get/set because the indices are in bounds by design
  let block = blocks.getOrUnconstrained(l2);
  let uint8x4 = UInt8x4.from(block.getOrUnconstrained(l1).toBytesBE());
  uint8x4.setOrDoNothing(l0, UInt8.from(0x80));
  block.setOrDoNothing(l1, UInt32.fromBytesBE(uint8x4.array));
  blocks.setOrDoNothing(l2, block);

  // set last 64 bits to encoded length (in bits, big-endian encoded)
  // in fact, since dynamic array asserts that length fits in 16 bits, we can set the second to last uint32 to 0
  let lastBlock = blocks.getOrUnconstrained(lastBlockIndex.value);
  lastBlock.set(14, UInt32.from(0));
  lastBlock.set(15, UInt32.Unsafe.fromField(message.length.mul(8))); // length in bits
  blocks.setOrDoNothing(lastBlockIndex.value, lastBlock);

  return blocks;
}

function splitMultiIndex(index: UInt32) {
  let { rest: l0, quotient: l1 } = index.divMod(64);
  let { rest: l00, quotient: l01 } = l0.divMod(4);
  return [l00.value, l01.value, l1.value] as const;
}

/**
 * Apply padding to dynamic-length input bytes and convert them to (a dynamic number of) blocks of 16 uint64s.
 */
function padding512(
  message: DynamicArray<UInt8>
): DynamicArray<StaticArray<UInt64>> {
  /* padded message looks like this:
  
  M ... M 0x80 0x0 ... 0x0 [...L[16]]

  where
  - M is the original message
  - the 16 L bytes encode the length of the original message, as a uint128
  - padding always starts with a 0x80 byte (= big-endian encoding of 1)
  - there are k 0x0 bytes, where k is the smallest number such that
    the padded length (in bytes) is a multiple of 128

  Corollaries:
  - the entire L section is always contained at the end of the last block
  - the 0x80 byte might be in the last block or the one before that
  - max number of blocks = ceil((M.maxLength + 17) / 128) 
  - number of actual blocks = ceil((M.length + 17) / 128) = floor((M.length + 17 + 127) / 128) = floor((M.length + 16) / 128) + 1
  - block number of L section = floor((M.length + 16) / 128)
  - block number of 0x80 byte index = floor(M.length / 128)
  */

  // check that all message bytes beyond the actual length are 0, so that we get valid padding just by adding the 0x80 and L bytes
  // this step creates most of the constraint overhead of dynamic sha2, but seems unavoidable :/
  message.forEach((byte, isPadding) => {
    Provable.assertEqualIf(isPadding, UInt8, byte, UInt8.from(0));
  });

  // create blocks of 128 bytes each
  const maxBlocks = Math.ceil((message.maxLength + 17) / 128);
  const BlocksOfBytes = DynamicArray(UInt8x128, { maxLength: maxBlocks });

  let lastBlockIndex = UInt32.Unsafe.fromField(message.length.add(16)).div(128);
  let numberOfBlocks = lastBlockIndex.value.add(1);
  let padded = pad(message.array, maxBlocks * 128, UInt8.from(0));
  let chunked = chunk(padded, 128).map(UInt8x128.from);
  let blocksOfBytes = new BlocksOfBytes(chunked, numberOfBlocks);

  // pack each block of 64 bytes into 16 uint64s (8 bytes each)
  let blocks = blocksOfBytes.map(Block64, (block) =>
    block.chunk(8).map(UInt64, (b) => uint64FromBytesBE(b.array))
  );

  // splice the length in the same way
  // length = l0 + 8*l1 + 128*l2
  // so that l2 is the block index, l1 the uint64 index in the block, and l0 the byte index in the uint64
  let [l0, l1, l2] = splitMultiIndex64(UInt32.Unsafe.fromField(message.length));

  // hierarchically get byte at `length` and set to 0x80
  // we can use unsafe get/set because the indices are in bounds by design
  let block = blocks.getOrUnconstrained(l2);
  let uint8x8 = UInt8x8.from(uint64ToBytesBE(block.getOrUnconstrained(l1)));
  uint8x8.setOrDoNothing(l0, UInt8.from(0x80));
  block.setOrDoNothing(l1, uint64FromBytesBE(uint8x8.array));
  blocks.setOrDoNothing(l2, block);

  // set last 128 bits to encoded length (in bits, big-endian encoded)
  // in fact, since dynamic array asserts that length fits in 16 bits, we can set the second to last uint64 to 0
  let lastBlock = blocks.getOrUnconstrained(lastBlockIndex.value);
  lastBlock.set(14, UInt64.from(0));
  lastBlock.set(15, UInt64.Unsafe.fromField(message.length.mul(8))); // length in bits
  blocks.setOrDoNothing(lastBlockIndex.value, lastBlock);

  return blocks;
}

function splitMultiIndex64(index: UInt32) {
  let { rest: l0, quotient: l1 } = index.divMod(128);
  let { rest: l00, quotient: l01 } = l0.divMod(8);
  return [l00.value, l01.value, l1.value] as const;
}
