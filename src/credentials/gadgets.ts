/**
 * Misc gadgets for attestation contracts.
 */
import { Bool, Field, Gadgets, Provable, UInt32 } from 'o1js';
import { assert } from '../util.ts';

export { pack, unsafeIf, seal, lessThan16, assertInRange16, assertLessThan16 };

/**
 * Pack a list of fields of bit size `chunkSize` each into a single field.
 * Uses little-endian encoding.
 *
 * **Warning**: Assumes, but doesn't prove, that each chunk fits in the chunk size.
 */
function pack(chunks: Field[], chunkSize: number) {
  let p = chunks.length * chunkSize;
  assert(
    p < Field.sizeInBits,
    () => `pack(): too many chunks, got ${chunks.length} * ${chunkSize} = ${p}`
  );
  let sum = Field(0);
  chunks.forEach((chunk, i) => {
    sum = sum.add(chunk.mul(1n << BigInt(i * chunkSize)));
  });
  return sum.seal();
}

/**
 * Slightly more efficient version of Provable.if() which produces garbage if both t is a non-dummy and b is true.
 *
 * t + b*s
 *
 * Cost: 2*|T|, or |T| if t is all zeros
 */
function unsafeIf<T>(b: Bool, type: Provable<T>, t: T, s: T): T {
  let fields = add(type.toFields(t), mul(type.toFields(s), b));
  let aux = type.toAuxiliary(t);
  Provable.asProver(() => {
    if (b.toBoolean()) aux = type.toAuxiliary(s);
  });
  return type.fromFields(fields, aux);
}

function seal<T>(type: Provable<T>, t: T): T {
  let fields = type.toFields(t);
  let aux = type.toAuxiliary(t);
  fields = fields.map((x) => x.seal());
  return type.fromFields(fields, aux);
}

function mul(fields: Field[], mask: Bool) {
  return fields.map((x) => x.mul(mask.toField()));
}
function add(t: Field[], s: Field[]) {
  return t.map((t, i) => t.add(s[i]!));
}

/**
 * Asserts that 0 <= i <= x without other assumptions on i,
 * assuming that 0 <= x < 2^16.
 */
function assertInRange16(i: Field, x: Field | number) {
  Gadgets.rangeCheck16(i);
  Gadgets.rangeCheck16(Field(x).sub(i).seal());
}

/**
 * Asserts that i < x, assuming that i in [0,2^32) and x in [0,2^16).
 *
 * Cost: 1.5
 */
function assertLessThan16(i: UInt32, x: Field | number) {
  if (i.isConstant() && Field(x).isConstant()) {
    assert(i.toBigint() < Field(x).toBigInt(), 'assertLessThan16');
  }
  // assumptions on i, x imply that x - 1 - i is in [0, 2^16) - 1 - [0, 2^32) = [-1-2^32, 2^16-1) = (p-2^32, p) u [0, 2^16-1)
  // checking 0 <= x - 1 - i < 2^16 excludes the negative part of the range
  Gadgets.rangeCheck16(Field(x).sub(1).sub(i.value).seal());
}

/**
 * Returns i <? x for i, x < 2^16.
 *
 * Note: This is also sound for i < 2^32, just not complete in that case
 *
 * Cost: 2.5
 */
function lessThan16(i: Field, x: Field | number): Bool {
  let b = Provable.witness(Field, () =>
    BigInt(i.toBigInt() < Field(x).toBigInt())
  );
  let isLessThan = b.assertBool();
  Gadgets.rangeCheck16(
    b
      .mul(1n << 16n)
      .add(i)
      .sub(x)
  );
  return isLessThan;
}
