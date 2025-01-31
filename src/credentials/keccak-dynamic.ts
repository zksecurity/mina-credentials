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
  const len = 256;
  let bytes = hash(Bytes.from(message), len / 8, len / 4, false);
  return BytesOfBitlength[len].from(bytes);
}

// KECCAK HASH FUNCTION

// Keccak hash function with input message passed as list of Field bytes.
// The message will be parsed as follows:
// - the first byte of the message will be the least significant byte of the first word of the state (A[0][0])
// - the 10*1 pad will take place after the message, until reaching the bit length rate.
// - then, {0} pad will take place to finish the 200 bytes of the state.
function hash(
  message: Bytes,
  length: number,
  capacity: number,
  nistVersion: boolean
): UInt8[] {
  // Throw errors if used improperly
  assert(capacity > 0, 'capacity must be positive');
  assert(
    capacity < STATE_LENGTH_BYTES,
    `capacity must be less than ${STATE_LENGTH_BYTES}`
  );
  assert(length > 0, 'length must be positive');

  // convert capacity and length to word units
  assert(capacity % 8 === 0, 'length must be a multiple of 8');
  capacity /= 8;
  assert(length % 8 === 0, 'length must be a multiple of 8');
  length /= 8;

  const rate = STATE_LENGTH_WORDS - capacity;

  // apply padding, convert to words, and hash
  const paddedBytes = pad(message.bytes, rate * 8, nistVersion);
  const padded = bytesToWords(paddedBytes);

  const hash = sponge(padded, length, capacity, rate);
  const hashBytes = wordsToBytes(hash);

  return hashBytes;
}

// Computes the number of required extra bytes to pad a message of length bytes
function bytesToPad(rate: number, length: number): number {
  return rate - (length % rate);
}

// Pads a message M as:
// M || pad[x](|M|)
// The padded message will start with the message argument followed by the padding rule (below) to fulfill a length that is a multiple of rate (in bytes).
// If nist is true, then the padding rule is 0x06 ..0*..1.
// If nist is false, then the padding rule is 10*1.
function pad(message: UInt8[], rate: number, nist: boolean): UInt8[] {
  // Find out desired length of the padding in bytes
  // If message is already rate bits, need to pad full rate again
  const extraBytes = bytesToPad(rate, message.length);

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
    rate + capacity === STATE_LENGTH_WORDS,
    `invalid rate or capacity (rate + capacity should be ${STATE_LENGTH_WORDS})`
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

// Length of the state in words, 5x5 = 25
const STATE_LENGTH_WORDS = 25;

// Length of the state in bytes, meaning the 5x5 matrix of words in bytes (200)
const STATE_LENGTH_BYTES = STATE_LENGTH_WORDS * 8;

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
