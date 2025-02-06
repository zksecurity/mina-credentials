/**
 * RSA signature verification with o1js
 *
 * This is copied and modified from an example in the o1js repo: https://github.com/o1-labs/o1js/tree/main/src/examples/crypto/rsa
 */
import { Bytes, Field, Gadgets, Provable, Struct, Unconstrained } from 'o1js';
import { TypeBuilder } from '../provable-type-builder.ts';
import { assert, chunk, fill } from '../util.ts';
import { pack, packBytes, unpack } from '../dynamic/gadgets.ts';
import { power } from './utils.ts';

export { Bigint2048, rsaVerify65537, rsaSign };

const mask = (1n << 116n) - 1n;

/**
 * We use 116-bit limbs, which means 18 limbs for 2048-bit numbers as used in RSA.
 */
const Field18 = Provable.Array(Field, 18);

class Bigint2048 {
  fields: Field[];
  value: Unconstrained<bigint>;

  constructor(props: { fields: Field[]; value: Unconstrained<bigint> }) {
    this.fields = props.fields;
    this.value = props.value;
  }

  modMul(x: Bigint2048, y: Bigint2048) {
    return multiply(x, y, this);
  }

  modSquare(x: Bigint2048) {
    return multiply(x, x, this, { isSquare: true });
  }

  toBigint() {
    return this.value.get();
  }

  static from(x: bigint | Bigint2048) {
    return Bigint2048.provable.fromValue(x);
  }

  static unsafeFromLimbs(fields: Field[]) {
    assert(fields.length === 18, 'expected 18 limbs');
    let value = Unconstrained.witness(() => {
      let x = 0n;
      for (let i = 17; i >= 0; i--) {
        x <<= 116n;
        x += fields[i]!.toBigInt();
      }
      return x;
    });
    return new Bigint2048({ fields, value });
  }

  static provable = TypeBuilder.shape({
    fields: Field18,
    value: Unconstrained.withEmpty(0n),
  })
    .forClass(Bigint2048)
    .replaceCheck((x) => {
      for (let i = 0; i < 18; i++) {
        rangeCheck116(x.fields[i]!);
      }
    })
    .mapValue({
      there: (x) => x.value,
      back: (x: bigint) => {
        let fields = [];
        let value = x;
        for (let i = 0; i < 18; i++) {
          fields.push(x & mask);
          x >>= 116n;
        }
        return { fields, value };
      },
      distinguish(x) {
        return typeof x !== 'bigint';
      },
    })
    .build();
}

/**
 * x*y mod p
 */
function multiply(
  x: Bigint2048,
  y: Bigint2048,
  p: Bigint2048,
  { isSquare = false } = {}
) {
  if (isSquare) y = x;

  // witness q, r so that x*y = q*p + r
  // this also adds the range checks in `check()`
  let { q, r } = Provable.witness(
    // TODO Struct() should be unnecessary
    Struct({ q: Bigint2048, r: Bigint2048 }),
    () => {
      let xy = x.toBigint() * y.toBigint();
      let p0 = p.toBigint();
      let q = xy / p0;
      let r = xy - q * p0;
      return { q, r };
    }
  );

  // compute delta = xy - qp - r
  // we can use a sum of native field products for each limb, because
  // input limbs are range-checked to 116 bits, and 2*116 + log(2*18-1) = 232 + 6 fits the native field.
  let delta: Field[] = Array.from({ length: 2 * 18 - 1 }, () => Field(0));
  let [X, Y, Q, R, P] = [x.fields, y.fields, q.fields, r.fields, p.fields];

  for (let i = 0; i < 18; i++) {
    // when squaring, we can save constraints by not computing xi * xj twice
    if (isSquare) {
      for (let j = 0; j < i; j++) {
        delta[i + j] = delta[i + j]!.add(X[i]!.mul(X[j]!).mul(2n));
      }
      delta[2 * i] = delta[2 * i]!.add(X[i]!.mul(X[i]!));
    } else {
      for (let j = 0; j < 18; j++) {
        delta[i + j] = delta[i + j]!.add(X[i]!.mul(Y[j]!));
      }
    }

    for (let j = 0; j < 18; j++) {
      delta[i + j] = delta[i + j]!.sub(Q[i]!.mul(P[j]!));
    }

    delta[i] = delta[i]!.sub(R[i]!).seal();
  }

  // perform carrying on the difference to show that it is zero
  let carry = Field(0);

  for (let i = 0; i < 2 * 18 - 2; i++) {
    let deltaPlusCarry = delta[i]!.add(carry).seal();

    carry = Provable.witness(Field, () => deltaPlusCarry.div(1n << 116n));
    rangeCheck128Signed(carry);

    // (xy - qp - r)_i + c_(i-1) === c_i * 2^116
    // proves that bits i*116 to (i+1)*116 of res are zero
    deltaPlusCarry.assertEquals(carry.mul(1n << 116n));
  }

  // last carry is 0 ==> all of diff is 0 ==> x*y = q*p + r as integers
  delta[2 * 18 - 2]!.add(carry).assertEquals(0n);

  return r;
}

/**
 * RSA signature verification,
 * assuming a public exponent of e = 65537
 *
 * Scheme: RSASSA-PKCS1-v1.5
 *
 * Spec:
 * https://datatracker.ietf.org/doc/html/rfc3447#section-8.2
 */
function rsaVerify65537(
  message: Bytes,
  signature: Bigint2048,
  modulus: Bigint2048
) {
  // e = 65537 = 2^16 + 1
  // compute signature^(2^16 + 1) mod modulus
  // => square 16 times
  let x = signature;
  for (let i = 0; i < 16; i++) {
    x = modulus.modSquare(x);
  }
  // multiply by signature once more
  x = modulus.modMul(x, signature);

  // check that x == padded message
  // TODO: need an error message here, this is where a wrong signature would be detected
  Provable.assertEqual(Bigint2048, x, rsaPadding(message));
}

/**
 * Pad 32-byte message to 2048-bit RSA bigint
 *
 * Scheme: EMSA-PKCS1-v1.5
 *
 * Spec:
 * https://datatracker.ietf.org/doc/html/rfc3447#section-9.2
 */
function rsaPadding(message: Bytes) {
  assert(message.length === 32, 'message must be 32 bytes');

  // reverse DER encoding of `DigestInfo` for message
  // EM = 0x00 || 0x01 || PS || 0x00 || T
  // reverse everything because the RFC views integers big-endian

  // SHA-256: T= (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H
  let derPadding = 0x30_31_30_0d_06_09_60_86_48_01_65_03_04_02_01_05_00_04_20n;

  // first, we encode the 32 message bytes, in reverse order, into the first three 116-bit limbs
  // because 116 / 8 = 14.5, one byte has to be split into two halves:
  // 32 = (14 + 0.5) + (0.5 + 14) + 3
  let bytes = message.bytes.toReversed(); // reverse so we can use little-endian encoding

  // TODO: I think we might have to reverse the bits within each byte as well :/

  let l0 = packBytes(bytes.slice(0, 14));
  let [l0half, l1half] = unpack(bytes[14]!.value, 4, 2);
  l0 = l0.add(l0half.mul(1n << 112n)).seal();
  let l1 = packBytes(bytes.slice(15, 29));
  l1 = l1half.add(l1.mul(1n << 4n)).seal();
  let l2 = packBytes(bytes.slice(29, 32));

  // l2 is filled up with 14.5 - 3 = 11.5 bytes = 92 bits of constant padding
  let l2Padding = derPadding & ((1n << 92n) - 1n); // lower 92 bits of DER padding
  l2 = l2.add(l2Padding << 24n).seal();

  // construct the entire remaining padding as 4-bit pieces

  // PS fills up the remaining space with 0xf pieces
  let psSize = 2048 / 4 - 6 - 64 - 38; // -38 comes from the DER padding

  // prettier-ignore
  let remaining = [
    // remaining DER padding
    ...unpack(derPadding >> 92n, 4, (19 - 11.5)*2).map((x) => Number(x)),
    // 0x00 || PS || 0x01 || 0x00
    0, 0, ...fill(psSize, 0xf), 1, 0, 0, 0,
    // additional 40 bits of 0-padding to fill up from 2048 bits to 116 * 18 = 2088 bits
    ...fill(10, 0x0)
  ];
  let remainingLimbs = chunk(remaining, 116 / 4).map((limb) =>
    pack(limb.map(Field), 4)
  );
  return Bigint2048.unsafeFromLimbs([l0, l1, l2, ...remainingLimbs]);
}

/**
 * Generates an RSA signature for the given message using the private key d and modulus n,
 * according to RSASSA-PKCS1-v1.5
 *
 * Returns the signature as a bigint.
 *
 * Notes:
 * - Expects an already hashed input, rather than performing the sha256 hash itself
 * - This method is not provable!
 */
function rsaSign(message: Bytes, keys: { d: bigint; n: bigint }): bigint {
  let paddedMessage = rsaPadding(message).toBigint();
  // Calculate the signature using modular exponentiation
  return power(paddedMessage, keys.d, keys.n);
}

// helpers

/**
 * Custom range check for a single limb, x in [0, 2^116)
 */
function rangeCheck116(x: Field) {
  let [x0, x1] = Provable.witnessFields(2, () => [
    x.toBigInt() & ((1n << 64n) - 1n),
    x.toBigInt() >> 64n,
  ]);

  Gadgets.rangeCheck64(x0);
  let [x52] = Gadgets.rangeCheck64(x1);
  x52.assertEquals(0n); // => x1 is 52 bits
  // 64 + 52 = 116
  x0.add(x1.mul(1n << 64n)).assertEquals(x);
}

/**
 * Custom range check for carries, x in [-2^127, 2^127)
 */
function rangeCheck128Signed(xSigned: Field) {
  let x = xSigned.add(1n << 127n);

  let [x0, x1] = Provable.witnessFields(2, () => {
    const x0 = x.toBigInt() & ((1n << 64n) - 1n);
    const x1 = x.toBigInt() >> 64n;
    return [x0, x1];
  });

  Gadgets.rangeCheck64(x0);
  Gadgets.rangeCheck64(x1);

  x0.add(x1.mul(1n << 64n)).assertEquals(x);
}
