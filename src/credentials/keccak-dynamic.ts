// the code in this file was copied and modified from o1js
// https://github.com/o1-labs/o1js
import { Bytes, Field, UInt8 } from 'o1js';
import { assert, chunk } from '../util.ts';
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
    lengthWords: 4, // 256 = 4*64 bits
    capacityWords: 8, // 512 = 8*64 bits
    nistVersion: false,
  });
  return BytesOfBitlength[256].from(bytes);
}

// KECCAK HASH FUNCTION

// Keccak hash function with input message passed as list of Field bytes.
// The message will be parsed as follows:
// - the first byte of the message will be the least significant byte of the first word of the state (A[0][0])
// - the 10*1 pad will take place after the message, until reaching the bit length rate.
// - then, {0} pad will take place to finish the 200 bytes of the state.
function hash(
  message: Bytes,
  {
    lengthWords,
    capacityWords,
    nistVersion,
  }: { lengthWords: number; capacityWords: number; nistVersion: boolean }
): UInt8[] {
  let rateWords = 25 - capacityWords; // 25 - 8 = 17

  // apply padding, convert to words, and hash
  const paddedBytes = pad(message.bytes, rateWords * 8, nistVersion);
  const padded = bytesToWords(paddedBytes);

  const hash = sponge(padded, lengthWords, capacityWords, rateWords);
  const hashBytes = wordsToBytes(hash);

  return hashBytes;
}

// Pads a message M as:
// M || pad[x](|M|)
// The padded message will start with the message argument followed by the padding rule (below) to fulfill a length that is a multiple of rate (in bytes).
// If nist is true, then the padding rule is 0x06 ..0*..1.
// If nist is false, then the padding rule is 10*1.
function pad(message: UInt8[], rateBytes: number, nist: boolean): UInt8[] {
  // Find out desired length of the padding in bytes
  // If message is already rate bits, need to pad full rate again
  const extraBytes = rateBytes - (message.length % rateBytes);

  // 0x06 0x00 ... 0x00 0x80 or 0x86
  const first = nist ? 0x06n : 0x01n;
  const last = 0x80n;

  // Create the padding vector
  const pad = Array<UInt8>(extraBytes).fill(UInt8.from(0));
  pad[0] = UInt8.from(first);
  pad[extraBytes - 1] = pad[extraBytes - 1]!.add(last);

  // Return the padded message
  return [...message, ...pad];
}

// KECCAK SPONGE

// Keccak sponge function for 200 bytes of state width
function sponge(
  paddedMessage: Field[],
  length: number,
  capacity: number,
  rate: number
): Field[] {
  // check that the padded message is a multiple of rate
  assert(paddedMessage.length % rate === 0, 'Invalid padded message length');

  // absorb
  const state = absorb(paddedMessage, capacity, rate, ROUND_CONSTANTS);

  // squeeze
  const hashed = squeeze(state, length, rate);
  return hashed;
}

// Absorb padded message into a keccak state with given rate and capacity
function absorb(
  paddedMessage: Field[],
  capacity: number,
  rate: number,
  rc: bigint[]
): State {
  assert(
    rate + capacity === 25,
    `rate + capacity should be equal to the state length`
  );
  assert(
    paddedMessage.length % rate === 0,
    'invalid padded message length (should be multiple of rate)'
  );

  let state = State.zeros();

  // array of capacity zero words
  const zeros = Array(capacity).fill(Field.from(0));

  for (let idx = 0; idx < paddedMessage.length; idx += rate) {
    // split into blocks of rate words
    const block = paddedMessage.slice(idx, idx + rate);
    // pad the block with 0s to up to KECCAK_STATE_LENGTH_WORDS words
    const paddedBlock = block.concat(zeros);
    // convert the padded block to a Keccak state
    const blockState = State.fromWords(paddedBlock);
    // xor the state with the padded block
    const stateXor = State.xor(state, blockState);
    // apply the permutation function to the xored state
    state = permutation(stateXor, rc);
  }
  return state;
}

// Squeeze state until it has a desired length in words
function squeeze(state: State, length: number, rate: number): Field[] {
  // number of squeezes
  const squeezes = Math.floor(length / rate) + 1;
  assert(squeezes === 1, 'squeezes should be 1');

  // Obtain the hash selecting the first `length` words of the output array
  const words = State.toWords(state);
  const hashed = words.slice(0, length);
  return hashed;
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
class Bytes48 extends Bytes(48) {}
class Bytes64 extends Bytes(64) {}

const BytesOfBitlength = {
  256: Bytes32,
  384: Bytes48,
  512: Bytes64,
};
