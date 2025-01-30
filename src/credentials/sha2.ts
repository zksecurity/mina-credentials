// the code in this file was copied and modified from o1js
// https://github.com/o1-labs/o1js
import {
  Bytes,
  Field,
  Gadgets,
  Provable,
  TupleN,
  UInt32,
  UInt64,
  UInt8,
} from 'o1js';
import { chunk, mod } from '../util.ts';
import { uint64FromBytesBE, uint64ToBytesBE } from './gadgets.ts';

export { SHA2 };

type FlexibleBytes = Bytes | (UInt8 | bigint | number)[] | Uint8Array | string;

// sha2 spec: https://csrc.nist.gov/pubs/fips/180-4/upd1/final

type Length = 224 | 256 | 384 | 512;

const SHA2 = {
  hash,
  padding256,
  padding512,
  initialState256,
  initialState512,
  messageSchedule256,
  messageSchedule512,
  compression256,
  compression512,
};

function hash(len: Length, data: FlexibleBytes) {
  if (len === 224 || len === 256) {
    return hash256(len, data);
  }
  if (len === 384 || len === 512) {
    return hash512(len, data);
  }
  throw Error('Unsupported hash length');
}

function hash256(len: 224 | 256, data: FlexibleBytes) {
  // preprocessing §6.2
  // padding the message $5.1.1 into blocks that are a multiple of 512
  let messageBlocks = padding256(data);

  let H = initialState256(len);

  messageBlocks.forEach((block) => {
    H = compression256(H, messageSchedule256(block));
  });

  if (len === 224) H = H.slice(0, 7); // 224 bit hash

  // the working variables H[i] are 32bit, however we want to decompose them into bytes to be more compatible
  return Bytes.from(H.map((x) => x.toBytesBE()).flat());
}

function hash512(len: 384 | 512, data: FlexibleBytes) {
  // preprocessing §6.2
  // padding the message $5.1.1 into blocks that are a multiple of 512
  let messageBlocks = padding512(data);

  let H = initialState512(len);

  messageBlocks.forEach((block) => {
    H = compression512(H, messageSchedule512(block));
  });

  if (len === 384) H = H.slice(0, 6); // 512 - 2*64 = 384 bit hash

  // decompose 64 bit fields into bytes
  return Bytes.from(H.flatMap((x) => uint64ToBytesBE(x)));
}

function initialState256(len: 224 | 256) {
  return constants[len].H.map((x) => UInt32.from(x));
}
function initialState512(len: 384 | 512) {
  return constants[len].H.map((x) => UInt64.from(x));
}

/**
 * Performs the SHA-256 compression function on the given hash values and message schedule.
 *
 * @param H - The initial or intermediate hash values (8-element array of UInt32).
 * @param W - The message schedule (64-element array of UInt32).
 *
 * @returns The updated intermediate hash values after compression.
 */
function compression256([...H]: UInt32[], W: UInt32[]) {
  // initialize working variables
  let a = H[0]!;
  let b = H[1]!;
  let c = H[2]!;
  let d = H[3]!;
  let e = H[4]!;
  let f = H[5]!;
  let g = H[6]!;
  let h = H[7]!;

  // main loop
  for (let t = 0; t < 64; t++) {
    // T1 is unreduced and not proven to be 32bit, we will do this later to save constraints
    const unreducedT1 = h.value
      .add(SigmaOne(e).value)
      .add(Ch(e, f, g).value)
      .add(constants[256].K[t]!)
      .add(W[t]!.value)
      .seal();

    // T2 is also unreduced
    const unreducedT2 = SigmaZero(a).value.add(Maj(a, b, c).value);

    h = g;
    g = f;
    f = e;
    e = UInt32.Unsafe.fromField(
      Gadgets.divMod32(d.value.add(unreducedT1), 48).remainder
    ); // mod 32bit the unreduced field element
    d = c;
    c = b;
    b = a;
    a = UInt32.Unsafe.fromField(
      Gadgets.divMod32(unreducedT2.add(unreducedT1), 48).remainder
    ); // mod 32bit
  }

  // new intermediate hash value
  H[0] = H[0]!.addMod32(a);
  H[1] = H[1]!.addMod32(b);
  H[2] = H[2]!.addMod32(c);
  H[3] = H[3]!.addMod32(d);
  H[4] = H[4]!.addMod32(e);
  H[5] = H[5]!.addMod32(f);
  H[6] = H[6]!.addMod32(g);
  H[7] = H[7]!.addMod32(h);

  return H;
}

/**
 * Performs the SHA-512 compression function on the given hash values and message schedule.
 *
 * @param H - The initial or intermediate hash values (8-element array of UInt64).
 * @param W - The message schedule (80-element array of UInt64).
 *
 * @returns The updated intermediate hash values after compression.
 */
function compression512([...H]: UInt64[], W: UInt64[]) {
  // initialize working variables
  let a = H[0]!;
  let b = H[1]!;
  let c = H[2]!;
  let d = H[3]!;
  let e = H[4]!;
  let f = H[5]!;
  let g = H[6]!;
  let h = H[7]!;

  // main loop
  for (let i = 0; i < 80; i++) {
    let S0 = sigma64(a, [28, 34, 39]);
    let S1 = sigma64(e, [14, 18, 41]);

    // T1 is unreduced and not proven to be 64-bit, we will do this later to save constraints
    const unreducedT1 = h.value
      .add(S1.value)
      .add(Ch64(e, f, g).value)
      .add(constants[512].K[i]!)
      .add(W[i]!.value)
      .seal();

    // T2 is also unreduced
    const unreducedT2 = S0.value.add(Maj64(a, b, c).value);

    h = g;
    g = f;
    f = e;
    e = UInt64.Unsafe.fromField(
      Gadgets.divMod64(d.value.add(unreducedT1), 64 + 16).remainder
    ); // mod 2^64
    d = c;
    c = b;
    b = a;
    a = UInt64.Unsafe.fromField(
      Gadgets.divMod64(unreducedT2.add(unreducedT1), 64 + 16).remainder
    ); // mod 2^64
  }

  // new intermediate hash value
  H[0] = H[0]!.addMod64(a);
  H[1] = H[1]!.addMod64(b);
  H[2] = H[2]!.addMod64(c);
  H[3] = H[3]!.addMod64(d);
  H[4] = H[4]!.addMod64(e);
  H[5] = H[5]!.addMod64(f);
  H[6] = H[6]!.addMod64(g);
  H[7] = H[7]!.addMod64(h);

  return H;
}

/**
 * Prepares the message schedule for the SHA-256 compression function from the given message block.
 *
 * @param M - The 512-bit message block (16-element array of UInt32).
 * @returns The message schedule (64-element array of UInt32).
 */
function messageSchedule256(M: UInt32[]) {
  // for each message block of 16 x 32bit do:
  const W: UInt32[] = [];

  // prepare message block
  for (let t = 0; t < 16; t++) W[t] = M[t]!;
  for (let t = 16; t < 64; t++) {
    // the field element is unreduced and not proven to be 32bit, we will do this later to save constraints
    let unreduced = DeltaOne(W[t - 2]!)
      .value.add(W[t - 7]!.value)
      .add(DeltaZero(W[t - 15]!).value.add(W[t - 16]!.value));

    // mod 32bit the unreduced field element
    W[t] = UInt32.Unsafe.fromField(Gadgets.divMod32(unreduced, 48).remainder);
  }

  return W;
}

/**
 * Prepares the message schedule for the SHA-512 compression function from the given message block.
 *
 * @param M - The 1024-bit message block (16-element array of UInt64).
 * @returns The message schedule (80-element array of UInt64).
 */
function messageSchedule512(M: UInt64[]) {
  // for each message block of 16 x 64 bit do:
  let W: UInt64[] = [];

  // prepare message block
  for (let i = 0; i < 16; i++) W[i] = M[i]!;
  for (let i = 16; i < 80; i++) {
    let s0 = sigma64(W[i - 15]!, [7, 8, 1], true);
    let s1 = sigma64(W[i - 2]!, [6, 19, 61], true);

    let unreduced = s1.value
      .add(W[i - 7]!.value)
      .add(s0.value.add(W[i - 16]!.value));

    // mod 64 bit the unreduced field element
    W[i] = UInt64.Unsafe.fromField(
      Gadgets.divMod64(unreduced, 64 + 16).remainder
    );
  }
  return W;
}

function padding256(data: FlexibleBytes): UInt32[][] {
  // create a provable Bytes instance from the input data
  // the Bytes class will be static sized according to the length of the input data
  if (typeof data === 'string') data = Bytes.fromString(data);
  let message = Bytes.from(data);

  // now pad the data to reach the format expected by sha256
  // pad 1 bit, followed by k zero bits where k is the smallest non-negative solution to
  // l + 1 + k = 448 mod 512
  // then append a 64bit block containing the length of the original message in bits

  let l = message.length * 8; // length in bits
  let k = Number(mod(448n - (BigInt(l) + 1n), 512n));

  let lBinary = l.toString(2);

  let paddingBits = (
    '1' + // append 1 bit
    '0'.repeat(k) + // append k zero bits
    '0'.repeat(64 - lBinary.length) + // append 64bit containing the length of the original message
    lBinary
  ).match(/.{1,8}/g)!; // this should always be divisible by 8

  // map the padding bit string to UInt8 elements
  let padding = paddingBits.map((x) => UInt8.from(BigInt('0b' + x)));

  // concatenate the padding with the original padded data
  let paddedMessage = message.bytes.concat(padding);

  // split the message into 32bit chunks
  let chunks: UInt32[] = [];

  for (let i = 0; i < paddedMessage.length; i += 4) {
    // chunk 4 bytes into one UInt32, as expected by SHA256
    // bytesToWord expects little endian, so we reverse the bytes
    chunks.push(UInt32.fromBytesBE(paddedMessage.slice(i, i + 4)));
  }

  // split message into 16 element sized message blocks
  // SHA256 expects n-blocks of 512bit each, 16*32bit = 512bit
  return chunk(chunks, 16);
}

function padding512(data: FlexibleBytes): UInt64[][] {
  if (typeof data === 'string') data = Bytes.fromString(data);
  let message = Bytes.from(data);

  // pad the data to reach the format expected by sha512
  // pad 1 bit, followed by k zero bits where k is the smallest non-negative solution to
  // l + 1 + k + 128 = 0 mod 1024
  // then append a 128-bit block containing the length of the original message in bits

  let l = message.length * 8; // length in bits
  let k = Number(mod(-BigInt(l) - 1n - 128n, 1024n));

  let lBinary = l.toString(2);

  let paddingBits = (
    '1' + // append 1 bit
    '0'.repeat(k) + // append k zero bits
    '0'.repeat(128 - lBinary.length) + // append 128 bit containing the length of the original message
    lBinary
  ).match(/.{1,8}/g)!; // this should always be divisible by 8

  // map the padding bit string to UInt8 elements
  let padding = paddingBits.map((x) => UInt8.from(BigInt('0b' + x)));

  // concatenate the padding with the original padded data
  let paddedMessage = message.bytes.concat(padding);

  // split the message into 64-bit chunks
  let chunks: UInt64[] = [];

  for (let i = 0; i < paddedMessage.length; i += 8) {
    // chunk 8 bytes into one UInt64
    chunks.push(uint64FromBytesBE(paddedMessage.slice(i, i + 8)));
  }

  // split message into 16 element sized message blocks
  // SHA256 expects n-blocks of 512bit each, 16*32bit = 512bit
  return chunk(chunks, 16);
}

// helpers

function Ch(x: UInt32, y: UInt32, z: UInt32) {
  // ch(x, y, z) = (x & y) ^ (~x & z)
  //             = (x & y) + (~x & z) (since x & ~x = 0)
  let xAndY = x.and(y).value;
  let xNotAndZ = x.not().and(z).value;
  let ch = xAndY.add(xNotAndZ).seal();
  return UInt32.Unsafe.fromField(ch);
}

function Maj(x: UInt32, y: UInt32, z: UInt32) {
  // maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)
  //              = (x + y + z - (x ^ y ^ z)) / 2
  let sum = x.value.add(y.value).add(z.value).seal();
  let xor = x.xor(y).xor(z).value;
  let maj = sum.sub(xor).div(2).seal();
  return UInt32.Unsafe.fromField(maj);
}

function SigmaZero(x: UInt32) {
  return sigma(x, [2, 13, 22]);
}

function SigmaOne(x: UInt32) {
  return sigma(x, [6, 11, 25]);
}

// lowercase sigma = delta to avoid confusing function names

function DeltaZero(x: UInt32) {
  return sigma(x, [3, 7, 18], true);
}

function DeltaOne(x: UInt32) {
  return sigma(x, [10, 17, 19], true);
}

function ROTR(n: number, x: UInt32) {
  return x.rotate(n, 'right');
}

function SHR(n: number, x: UInt32) {
  let val = x.rightShift(n);
  return val;
}

function sigmaSimple(u: UInt32, bits: TupleN<number, 3>, firstShifted = false) {
  let [r0, r1, r2] = bits;
  let rot0 = firstShifted ? SHR(r0, u) : ROTR(r0, u);
  let rot1 = ROTR(r1, u);
  let rot2 = ROTR(r2, u);
  return rot0.xor(rot1).xor(rot2);
}

function sigma(u: UInt32, bits: TupleN<number, 3>, firstShifted = false) {
  if (u.isConstant()) return sigmaSimple(u, bits, firstShifted);

  let [r0, r1, r2] = bits; // TODO assert bits are sorted
  let x = u.value;

  let d0 = r0;
  let d1 = r1 - r0;
  let d2 = r2 - r1;
  let d3 = 32 - r2;

  // decompose x into 4 chunks of size d0, d1, d2, d3
  let [x0, x1, x2, x3] = Provable.witnessFields(4, () => {
    let xx = x.toBigInt();
    return [
      bitSlice(xx, 0, d0),
      bitSlice(xx, r0, d1),
      bitSlice(xx, r1, d2),
      bitSlice(xx, r2, d3),
    ];
  });

  // range check each chunk
  // we only need to range check to 16 bits relying on the requirement that
  // the rotated values are range-checked to 32 bits later; see comments below
  Gadgets.rangeCheck16(x0);
  Gadgets.rangeCheck16(x1);
  Gadgets.rangeCheck16(x2);
  Gadgets.rangeCheck16(x3);

  // prove x decomposition

  // x === x0 + x1*2^d0 + x2*2^(d0+d1) + x3*2^(d0+d1+d2)
  let x23 = x2.add(x3.mul(1 << d2)).seal();
  let x123 = x1.add(x23.mul(1 << d1)).seal();
  x0.add(x123.mul(1 << d0)).assertEquals(x);
  // ^ proves that 2^(32-d3)*x3 < x < 2^32 => x3 < 2^d3

  // reassemble chunks into rotated values

  let xRotR0: Field;

  if (!firstShifted) {
    // rotr(x, r0) = x1 + x2*2^d1 + x3*2^(d1+d2) + x0*2^(d1+d2+d3)
    xRotR0 = x123.add(x0.mul(1 << (d1 + d2 + d3))).seal();
    // ^ proves that 2^(32-d0)*x0 < xRotR0 => x0 < 2^d0 if we check xRotR0 < 2^32 later
  } else {
    // shr(x, r0) = x1 + x2*2^d1 + x3*2^(d1+d2)
    xRotR0 = x123;

    // finish x0 < 2^d0 proof:
    Gadgets.rangeCheck16(x0.mul(1 << (16 - d0)).seal());
  }

  // rotr(x, r1) = x2 + x3*2^d2 + x0*2^(d2+d3) + x1*2^(d2+d3+d0)
  let x01 = x0.add(x1.mul(1 << d0)).seal();
  let xRotR1 = x23.add(x01.mul(1 << (d2 + d3))).seal();
  // ^ proves that 2^(32-d1)*x1 < xRotR1 => x1 < 2^d1 if we check xRotR1 < 2^32 later

  // rotr(x, r2) = x3 + x0*2^d3 + x1*2^(d3+d0) + x2*2^(d3+d0+d1)
  let x012 = x01.add(x2.mul(1 << (d0 + d1))).seal();
  let xRotR2 = x3.add(x012.mul(1 << d3)).seal();
  // ^ proves that 2^(32-d2)*x2 < xRotR2 => x2 < 2^d2 if we check xRotR2 < 2^32 later

  // since xor() is implicitly range-checking both of its inputs, this provides the missing
  // proof that xRotR0, xRotR1, xRotR2 < 2^32, which implies x0 < 2^d0, x1 < 2^d1, x2 < 2^d2
  return UInt32.Unsafe.fromField(xRotR0)
    .xor(UInt32.Unsafe.fromField(xRotR1))
    .xor(UInt32.Unsafe.fromField(xRotR2));
}

function Ch64(x: UInt64, y: UInt64, z: UInt64) {
  // ch(x, y, z) = (x & y) ^ (~x & z)
  //             = (x & y) + (~x & z) (since x & ~x = 0)
  let xAndY = x.and(y).value;
  let xNotAndZ = x.not().and(z).value;
  let ch = xAndY.add(xNotAndZ).seal();
  return UInt64.Unsafe.fromField(ch);
}

function Maj64(x: UInt64, y: UInt64, z: UInt64) {
  // maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)
  //              = (x + y + z - (x ^ y ^ z)) / 2
  let sum = x.value.add(y.value).add(z.value).seal();
  let xor = x.xor(y).xor(z).value;
  let maj = sum.sub(xor).div(2).seal();
  return UInt64.Unsafe.fromField(maj);
}

// TODO optimized version
function sigma64(u: UInt64, bits: TupleN<number, 3>, firstShifted = false) {
  let [r0, r1, r2] = bits;
  let rot0 = firstShifted ? u.rightShift(r0) : u.rotate(r0, 'right');
  let rot1 = u.rotate(r1, 'right');
  let rot2 = u.rotate(r2, 'right');
  return rot0.xor(rot1).xor(rot2);
}

function bitSlice(x: bigint, start: number, length: number) {
  return (x >> BigInt(start)) & ((1n << BigInt(length)) - 1n);
}

// constants §4.2.2
const roundConstants256 = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// prettier-ignore
const roundConstants512 = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn,
  0xe9b5dba58189dbbcn, 0x3956c25bf348b538n, 0x59f111f1b605d019n,
  0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n, 0xd807aa98a3030242n,
  0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n,
  0xc19bf174cf692694n, 0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n,
  0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n, 0x2de92c6f592b0275n,
  0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
  0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn,
  0xbf597fc7beef0ee4n, 0xc6e00bf33da88fc2n, 0xd5a79147930aa725n,
  0x06ca6351e003826fn, 0x142929670a0e6e70n, 0x27b70a8546d22ffcn,
  0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
  0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n,
  0x92722c851482353bn, 0xa2bfe8a14cf10364n, 0xa81a664bbc423001n,
  0xc24b8b70d0f89791n, 0xc76c51a30654be30n, 0xd192e819d6ef5218n,
  0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n,
  0x34b0bcb5e19b48a8n, 0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn,
  0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n, 0x748f82ee5defb2fcn,
  0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
  0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n,
  0xc67178f2e372532bn, 0xca273eceea26619cn, 0xd186b8c721c0c207n,
  0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n, 0x06f067aa72176fban,
  0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
  0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn,
  0x431d67c49c100d4cn, 0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an,
  0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n,
];

const constants = {
  224: {
    K: roundConstants256,
    H: [
      0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511,
      0x64f98fa7, 0xbefa4fa4,
    ],
  },
  256: {
    K: roundConstants256,
    // initial hash values §5.3.3
    H: [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
      0x1f83d9ab, 0x5be0cd19,
    ],
  },
  384: {
    K: roundConstants512,
    // prettier-ignore
    H: [
      0xcbbb9d5dc1059ed8n, 0x629a292a367cd507n, 0x9159015a3070dd17n, 0x152fecd8f70e5939n,
      0x67332667ffc00b31n, 0x8eb44a8768581511n, 0xdb0c2e0d64f98fa7n, 0x47b5481dbefa4fa4n,
    ],
  },
  512: {
    K: roundConstants512,
    // prettier-ignore
    H: [
      0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n, 
      0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
    ],
  },
};
