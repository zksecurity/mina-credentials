// the code in this file was copied and modified from o1js
// https://github.com/o1-labs/o1js
import { Bytes, Field, UInt8 } from 'o1js';
import { assert, chunk, pad } from '../util.ts';
import { packBytes, unpackBytes } from './gadgets.ts';
import { permutation, ROUND_CONSTANTS, State } from './keccak-permutation.ts';

export { keccak256 };

type FlexibleBytes = (UInt8 | bigint | number)[] | Uint8Array | Bytes;

/**
 * Ethereum-Compatible Keccak-256 Hash Function.
 * This is a specialized variant of {@link Keccak.preNist} configured for a 256-bit output length.
 *
 * Primarily used in Ethereum for hashing transactions, messages, and other types of payloads.
 *
 * The function accepts {@link Bytes} as the input message, which is a type that represents a static-length list of byte-sized field elements (range-checked using {@link Gadgets.rangeCheck8}).
 * Alternatively, you can pass plain `number[]` of `Uint8Array` to perform a hash outside provable code.
 *
 * Produces an output of {@link Bytes} of length 32. Both input and output bytes are big-endian.
 *
 * @param message - Big-endian {@link Bytes} representing the message to hash.
 *
 * ```ts
 * let preimage = Bytes.fromString("hello world");
 * let digest = Keccak.ethereum(preimage);
 * ```
 */
function keccak256(message: FlexibleBytes): Bytes {
  let bytes = hash(Bytes.from(message), {
    length: 4, // 256 = 4*64 bits
    capacity: 8, // 512 = 8*64 bits
    isNist: false,
  });
  return Bytes32.from(bytes);
}

// KECCAK HASH FUNCTION

// Keccak hash function with input message passed as list of Field bytes.
// The message will be parsed as follows:
// - the first byte of the message will be the least significant byte of the first word of the state (A[0][0])
// - the 10*1 pad will take place after the message, until reaching the bit length rate.
// - then, {0} pad will take place to finish the 200 bytes of the state.
function hash(
  message: Bytes,
  options: { length: number; capacity: number; isNist: boolean }
): UInt8[] {
  let rate = 25 - options.capacity;

  // apply padding, convert to blocks of words
  let blocks = padding(message.bytes, rate, options.isNist);

  // absorb
  let state = State.zeros();

  for (let block of blocks) {
    state = State.xor(state, block);
    state = permutation(state, ROUND_CONSTANTS);
  }

  // squeeze once
  // hash == first `length` words of the state
  assert(options.length < rate, 'length should be less than rate');
  let hash = State.toWords(state).slice(0, options.length);

  let hashBytes = wordsToBytes(hash);
  return hashBytes;
}

// Pads a message M as:
// M || pad[x](|M|)
// The padded message will start with the message argument followed by the padding rule (below) to fulfill a length that is a multiple of rate (in bytes).
// If nist is true, then the padding rule is 0x06 ..0*..1.
// If nist is false, then the padding rule is 10*1.
function padding(message: UInt8[], rate: number, isNist: boolean): State[] {
  // Find out desired length of the padding in bytes
  // If message is already rate bits, need to pad full rate again
  let rateBytes = rate * 8;
  let extraBytes = rateBytes - (message.length % rateBytes);

  // 0x06 0x00 ... 0x00 0x80 or 0x86
  let first = isNist ? 0x06n : 0x01n;
  let last = 0x80n;

  // Create the padding vector
  const paddingBytes = Array<UInt8>(extraBytes).fill(UInt8.from(0));
  paddingBytes[0] = UInt8.from(first);
  paddingBytes[extraBytes - 1] = paddingBytes[extraBytes - 1]!.add(last);

  // Return the padded message, converted to blocks of `rate` words
  let words = bytesToWords([...message, ...paddingBytes]);
  let blocks = chunk(words, rate);
  return blocks.map((block) => {
    // for convenience, each block is brought into the same shape as
    // the state, by appending `capacity` zeros
    let fullBlock = pad(block, 25, Field(0));
    return State.fromWords(fullBlock);
  });
}

// UTILITY FUNCTIONS

/**
 * Convert an array of 64-bit Fields to an array of UInt8.
 */
function wordsToBytes(words: Field[]): UInt8[] {
  return words.flatMap((w) => unpackBytes(w, 8));
}
/**
 * Convert an array of UInt8 to an array of 64-bit Fields.
 */
function bytesToWords(bytes: UInt8[]): Field[] {
  return chunk(bytes, 8).map((chunk) => packBytes(chunk));
}

// AUXILIARY TYPES

class Bytes32 extends Bytes(32) {}
