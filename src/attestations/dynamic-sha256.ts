import { Bytes, Field, Gadgets, Provable, UInt32, UInt8 } from 'o1js';
import { DynamicArray } from './dynamic-array.ts';
import { StaticArray } from './static-array.ts';
import { assert, chunk, pad } from '../util.ts';
const { SHA256 } = Gadgets;

export { DynamicSHA256 };

const DynamicSHA256 = {
  /**
   * Hash a dynamic-length byte array.
   */
  hash,
  /**
   * Apply padding to dynamic-length input bytes and convert them to (a dynamic number of) blocks of 16 uint32s.
   */
  padding,
};

// static array types for blocks / state / result
class UInt8x64 extends StaticArray(UInt8, 64) {}
class Block extends StaticArray(UInt32, 16) {}
class State extends StaticArray(UInt32, 8) {}
const Bytes32 = Bytes(32);

function hash(bytes: DynamicArray<UInt8>): Bytes {
  let blocks = padding(bytes);

  // hash a dynamic number of blocks using DynamicArray.reduce()
  let state = blocks.reduce(
    State,
    State.from(SHA256.initialState),
    (state: State, block: Block) => {
      let W = SHA256.createMessageSchedule(block.array);
      return State.from(SHA256.compression(state.array, W));
    }
  );

  let result = state.array.flatMap((x) => uint32ToBytesBE(x).array);
  return Bytes32.from(result);
}

function padding(
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
  - the 0x1 byte might be in the last block or the one before that
  - max number of blocks = ceil((M.maxLength + 9) / 64) 
  - number of actual blocks = ceil((M.length + 9) / 64) = floor((M.length + 9 + 63) / 64) = floor((M.length + 8) / 64) + 1
  - block number of L section = floor((M.length + 8) / 64)
  - block number of 0x1 byte index = floor(M.length / 64)
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
    block.chunk(4).map(UInt32, uint32FromBytesBE)
  );

  // splice the length in the same way
  // length = l0 + 4*l1 + 64*l2
  let [l0, l1, l2] = splitMultiIndex(UInt32.Unsafe.fromField(message.length));

  // hierarchically get byte at `length` and set to 0x80
  // we can use unsafe get/set because the indices are in bounds by design
  let block = blocks.getOrUnconstrained(l2);
  let uint8x4 = uint32ToBytesBE(block.getOrUnconstrained(l1));
  uint8x4.setOrDoNothing(l0, UInt8.from(0x80)); // big-endian encoding of 1
  block.setOrDoNothing(l1, uint32FromBytesBE(uint8x4));
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
  // prove that bytes are correct
  uint32FromBytes(bytes).assertEquals(word);
  return bytes;
}
function uint32ToBytesBE(word: UInt32) {
  return uint32ToBytes(word).toReversed();
}
