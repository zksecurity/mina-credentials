import { Bytes, Field, Provable, Struct, UInt32, UInt64, UInt8 } from 'o1js';
import { DynamicArray } from './dynamic-array.ts';
import { StaticArray } from './static-array.ts';
import { assert, chunk, pad } from '../util.ts';
import { SHA2 } from './sha2.ts';
import { uint64FromBytesBE, uint64ToBytesBE } from './gadgets.ts';
import { hashSafe } from './dynamic-hash.ts';
import { ProvableType, toFieldsPacked } from '../o1js-missing.ts';
import type { Constructor } from '../types.ts';

export {
  DynamicSHA2,
  Sha2IterationState,
  Sha2Iteration,
  Sha2FinalIteration,
  State32,
  State64,
  Block32,
  Block64,
  Bytes28,
  Bytes32,
  Bytes48,
  Bytes64,
};

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

  /**
   * `DynamicSHA2.split()` is the first part of a more flexible API which allows to split proving a SHA2 hash over multiple proofs.
   *
   * Input arguments:
   * - `len`: the output length in bits (224, 256, 384, or 512)
   * - `blocksPerIteration`: how many SHA2 blocks (64-128 bytes) to process in each proof/iteration. Reasonable values are 2-8.
   * - `bytes`: the input bytes to hash
   *
   * `split()` is called **outside provable code** and prepares the inputs to the different proofs:
   * - `initial`: the initial "state" of the iteration (which is independent of the string to be hashed, and also returned by `Sha2IterationState.initial()`)
   * - `iterations`: a sequence of chunks (several blocks each) of the input string, to be passed to `update()`
   * - `final`: the last chunk of the input string, to be passed to `finalize()`
   *
   * Gist of how to use `split()`, `update()`, and `finalize()`:
   * ```ts
   * // outside the circuit:
   * const BLOCKS_PER_ITERATION = 6;
   * let { initial, iterations, final } = DynamicSHA2.split(256, BLOCKS_PER_ITERATION, bytes);
   *
   * // inside "update" circuit, for every iteration:
   * state = DynamicSHA2.update(initial, iterations[0]);
   * // OR
   * state = DynamicSHA2.update(state, iterations[i]);
   *
   * // inside "finalize" circuit:
   * let hash = DynamicSHA2.finalize(state, final, bytes);
   * ```
   */
  split,

  /**
   * `update()` is the second part of the API for splitting a SHA2 hash proof.
   *
   * It takes the current `Sha2IterationState` and a `Sha2Iteration` (a chunk of blocks to be hashed) and returns the updated state.
   *
   * See `split()` for additional details.
   */
  update,

  /**
   * `finalize()` is the last part of the API for splitting a SHA2 hash proof.
   *
   * It takes the current `Sha2IterationState`, a `Sha2FinalIteration`, and the original input bytes, and returns the hash.
   * Since the `Sha2IterationState` contains a commitment to the previous blocks that were hashed, calling `finalize()` is able
   * to prove that the same input bytes were hashed across multiple iterations. Thus, after calling it you are able to use
   * the same input bytes in further statements.
   *
   * See `split()` for additional details.
   */
  finalize,

  // low-level API

  padding256,
  padding512,
  commitBlock256,
  commitBlock512,
  hashBlock256,
  hashBlock512,
  initialState256: (l: 224 | 256) => State32.from(SHA2.initialState256(l)),
  initialState512: (l: 384 | 512) => State64.from(SHA2.initialState512(l)),
};

function sha2(len: 224 | 256 | 384 | 512, bytes: DynamicArray<UInt8>): Bytes {
  if (len === 224 || len === 256) return hash256(len, bytes);
  if (len === 384 || len === 512) return hash512(len, bytes);
  throw new Error('unsupported hash length');
}

type Length = 224 | 256 | 384 | 512;

// static array types for blocks / state / result
class UInt8x4 extends StaticArray(UInt8, 4) {}
class UInt8x8 extends StaticArray(UInt8, 8) {}
class UInt8x64 extends StaticArray(UInt8, 64) {}
class UInt8x128 extends StaticArray(UInt8, 128) {}
class Block32 extends StaticArray(UInt32, 16) {}
class State32 extends StaticArray(UInt32, 8) {}
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
    State32,
    State32.from(SHA2.initialState256(len)),
    (state, block) => {
      let W = SHA2.messageSchedule256(block.array);
      return State32.from(SHA2.compression256(state.array, W));
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
): DynamicArray<StaticArray<UInt32>, bigint[]> {
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
  let blocks = blocksOfBytes.map(Block32, (block) =>
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

  // pack each block of 128 bytes into 16 uint64s (8 bytes each)
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

// updating API

type Sha2IterationState<L extends Length = Length> = L extends 224 | 256
  ? { len: L; state: State32; commitment: Field }
  : { len: L; state: State64; commitment: Field };

type Sha2Iteration<L extends Length = Length> = L extends 224 | 256
  ? { type: 256; blocks: StaticArray<Block32> }
  : { type: 512; blocks: StaticArray<Block64> };

type Sha2FinalIteration<L extends Length = Length> = L extends 224 | 256
  ? { type: 256; blocks: DynamicArray<Block32> }
  : { type: 512; blocks: DynamicArray<Block64> };

function initialState<L extends Length>(len: L): Sha2IterationState<L>;

function initialState(len: Length): Sha2IterationState {
  if (len === 224 || len === 256) {
    return {
      len,
      state: State32.from(SHA2.initialState256(len)),
      commitment: Field(0),
    };
  } else {
    return {
      len,
      state: State64.from(SHA2.initialState512(len)),
      commitment: Field(0),
    };
  }
}

function split<L extends Length>(
  len: L,
  blocksPerIteration: number,
  bytes: DynamicArray<UInt8>
): {
  initial: Sha2IterationState<L>;
  iterations: Sha2Iteration<L>[];
  final: Sha2FinalIteration<L>;
};

function split<L extends Length>(
  len: L,
  blocksPerIteration: number,
  bytes: DynamicArray<UInt8>
): {
  initial: Sha2IterationState<L>;
  iterations: Sha2Iteration[];
  final: Sha2FinalIteration;
} {
  let initial = initialState(len);

  if (len === 224 || len === 256) {
    let blocks = padding256(bytes);
    let [iterations, final] = blocks.chunk(blocksPerIteration);
    return {
      initial,
      iterations: iterations.array
        .slice(0, Number(iterations.length))
        .map((blocks) => ({ type: 256, blocks })),
      final: { type: 256, blocks: final },
    };
  } else {
    let blocks = padding512(bytes);
    let [iterations, final] = blocks.chunk(blocksPerIteration);
    return {
      initial,
      iterations: iterations.array
        .slice(0, Number(iterations.length))
        .map((blocks) => ({ type: 512, blocks })),
      final: { type: 512, blocks: final },
    };
  }
}

function update<L extends Length>(
  iterState: Sha2IterationState<L>,
  iteration: Sha2Iteration
): Sha2IterationState<L>;

function update(
  iterState: Sha2IterationState,
  iteration: Sha2Iteration
): Sha2IterationState {
  if (iterState.len === 224 || iterState.len === 256) {
    assert(iteration.type === 256, 'incompatible types');

    // update hash state and commitment
    let { state, commitment } = iterState;
    state = iteration.blocks.reduce(state, hashBlock256);
    commitment = iteration.blocks.reduce(commitment, commitBlock256);

    return { len: iterState.len, state, commitment };
  } else {
    assert(iterState.len === 384 || iterState.len === 512, 'invalid state');
    assert(iteration.type === 512, 'incompatible types');

    // update hash state and commitment
    let { state, commitment } = iterState;
    state = iteration.blocks.reduce(state, hashBlock512);
    commitment = iteration.blocks.reduce(commitment, commitBlock512);

    return { len: iterState.len, state, commitment };
  }
}

function finalize(
  iterState: Sha2IterationState,
  final: Sha2FinalIteration,
  bytes: DynamicArray<UInt8>
): Bytes {
  if (iterState.len === 224 || iterState.len === 256) {
    assert(final.type === 256, 'incompatible types');

    // update hash state and commitment
    let { state, commitment } = iterState;
    state = final.blocks.reduce(State32, state, hashBlock256);
    commitment = final.blocks.reduce(Field, commitment, commitBlock256);

    // recompute commitment from scratch to confirm we really hashed the input bytes
    let expected = padding256(bytes).reduce(Field, Field(0), commitBlock256);
    commitment.assertEquals(expected, 'invalid commitment');

    // finalize hash
    let result = state.array.flatMap((x) => x.toBytesBE());
    return iterState.len === 224 ? Bytes28.from(result) : Bytes32.from(result);
  } else {
    assert(iterState.len === 384 || iterState.len === 512, 'invalid state');
    assert(final.type === 512, 'incompatible types');

    // update hash state and commitment
    let { state, commitment } = iterState;
    state = final.blocks.reduce(State64, state, hashBlock512);
    commitment = final.blocks.reduce(Field, commitment, commitBlock512);

    // recompute commitment from scratch to confirm we really hashed the input bytes
    let expected = padding512(bytes).reduce(Field, Field(0), commitBlock512);
    commitment.assertEquals(expected, 'invalid commitment');

    // finalize hash
    let result = state.array.flatMap((x) => uint64ToBytesBE(x));
    return iterState.len === 384 ? Bytes48.from(result) : Bytes64.from(result);
  }
}

// provable types for update API

function Sha2IterationState<L extends Length>(len: L) {
  const S: Constructor<Sha2IterationState<L>> &
    Provable<
      Sha2IterationState<L>,
      { len: L; state: bigint[]; commitment: bigint }
    > = Struct({
    len: ProvableType.constant(len),
    state: State(len),
    commitment: Field,
  });
  return Object.assign(S, {
    initial() {
      return initialState(len);
    },
  });
}
Sha2IterationState.initial = initialState;

function Sha2Iteration<L extends Length>(
  len: L,
  blocksPerIteration: number
): Constructor<Sha2Iteration<L>> &
  Provable<Sha2Iteration<L>, { type: 256 | 512; blocks: bigint[][] }> {
  return Struct({
    type: ProvableType.constant(len === 224 || len === 256 ? 256 : 512),
    blocks: StaticArray(Block(len), blocksPerIteration),
  });
}

function Sha2FinalIteration<L extends Length>(
  len: L,
  blocksPerIteration: number
): Constructor<Sha2FinalIteration<L>> &
  Provable<Sha2FinalIteration<L>, { type: 256 | 512; blocks: bigint[][] }> {
  return Struct({
    type: ProvableType.constant(len === 224 || len === 256 ? 256 : 512),
    blocks: DynamicArray(Block(len), { maxLength: blocksPerIteration }),
  });
}

// helpers for update API

function hashBlock256(state: State32, block: Block32): State32 {
  let W = SHA2.messageSchedule256(block.array);
  return State32.from(SHA2.compression256(state.array, W));
}
function hashBlock512(state: State64, block: Block64): State64 {
  let W = SHA2.messageSchedule512(block.array);
  return State64.from(SHA2.compression512(state.array, W));
}

// poseidon hash for keeping a commitment to the blocks that were hashed
function commitBlock256(commitment: Field, block: Block32): Field {
  let blockHash = hashSafe(toFieldsPacked(Block32, block));
  return hashSafe([commitment, blockHash]);
}
function commitBlock512(commitment: Field, block: Block64): Field {
  let blockHash = hashSafe(toFieldsPacked(Block64, block));
  return hashSafe([commitment, blockHash]);
}

function Block(len: 224 | 256 | 384 | 512) {
  return len === 224 || len === 256 ? Block32 : Block64;
}
function State(len: 224 | 256 | 384 | 512) {
  return len === 224 || len === 256 ? State32 : State64;
}
