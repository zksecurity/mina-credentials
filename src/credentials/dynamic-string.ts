import {
  Bool,
  Field,
  Poseidon,
  Provable,
  type ProvableHashable,
  UInt32,
  UInt8,
} from 'o1js';
import {
  DynamicArray,
  DynamicArrayBase,
  provableDynamicArray,
} from './dynamic-array.ts';
import { ProvableFactory } from '../provable-factory.ts';
import { assert, pad, stringLength } from '../util.ts';
import { BaseType } from './dynamic-base-types.ts';
import { DynamicSHA2 } from './dynamic-sha2.ts';
import { packBytes } from './gadgets.ts';
import { StaticArray } from './static-array.ts';

export { DynamicString };

type DynamicString = DynamicStringBase;

/**
 * Specialization of `DynamicArray` to string (represented as array of bytes),
 * with added helper methods to create instances.
 *
 * ```ts
 * const String = DynamicString({ maxLength: 120 });
 *
 * let string = String.from('hello');
 * ```
 */
function DynamicString({ maxLength }: { maxLength: number }) {
  // assert maxLength bounds
  assert(maxLength >= 0, 'maxLength must be >= 0');
  assert(maxLength < 2 ** 16, 'maxLength must be < 2^16');

  class DynamicString extends DynamicStringBase {
    static get maxLength() {
      return maxLength;
    }
    static get provable() {
      return provableString;
    }

    /**
     * Create DynamicBytes from a string.
     */
    static from(s: string | DynamicStringBase) {
      return provableString.fromValue(s);
    }
  }

  const provableString = provableDynamicArray<
    UInt8,
    { value: bigint },
    typeof DynamicStringBase
  >(UInt8 as any, DynamicString)
    .mapValue<string>({
      there(s) {
        return dec.decode(Uint8Array.from(s, ({ value }) => Number(value)));
      },
      backAndDistinguish(s) {
        // gracefully handle different maxLength
        if (s instanceof DynamicStringBase) {
          if (s.maxLength === maxLength) return s;
          if (s.maxLength < maxLength) return s.growMaxLengthTo(maxLength);
          // shrinking max length will only work outside circuit
          s = s.toString();
        }
        return [...enc.encode(s)].map((t) => ({ value: BigInt(t) }));
      },
    })
    .build();

  return DynamicString;
}

DynamicString.from = function (s: string | DynamicStringBase) {
  if (typeof s !== 'string') return s;
  return DynamicString({ maxLength: stringLength(s) }).from(s);
};

BaseType.DynamicString = DynamicString;

const enc = new TextEncoder();
const dec = new TextDecoder();

class DynamicStringBase extends DynamicArrayBase<UInt8, { value: bigint }> {
  get innerType() {
    return UInt8 as any as ProvableHashable<UInt8, { value: bigint }>;
  }

  /**
   * Hash the string using variants of SHA2.
   */
  hashToBytes(algorithm: 'sha2-256' | 'sha2-384' | 'sha2-512') {
    switch (algorithm) {
      case 'sha2-256':
        return DynamicSHA2.hash(256, this);
      case 'sha2-384':
        return DynamicSHA2.hash(384, this);
      case 'sha2-512':
        return DynamicSHA2.hash(512, this);
      default:
        assert(false, 'unsupported hash kind');
    }
  }

  /**
   * Convert DynamicBytes to a string.
   */
  toString() {
    return this.toValue() as any as string;
  }

  /**
   * Concatenate two strings.
   *
   * The resulting (max)length is the sum of the two individual (max)lengths.
   *
   * Note: This overrides the naive `concat()` implementation in `DynamicArray`.
   * It's much more efficient than the base method and than both `concatTransposed()` and `concatByHashing()`.
   */
  concat(other: DynamicArray<UInt8>): DynamicString {
    const CHARS_PER_BLOCK = 8; // hand-fitted to optimize constraints for (100, 100) and (100, 20) concat

    // divide both strings into smaller blocks of chars
    let [aBlocks, aTrailingBlock] = this.chunk(CHARS_PER_BLOCK);
    let [bBlocks, bTrailingBlock] = other.chunk(CHARS_PER_BLOCK);

    // we hash each complete block of the first string
    let aHash = aBlocks.reduce(Field, Field(0), (hash, block) => {
      return Poseidon.hash([hash, packBytes(block.array)]);
    });

    // the trailing a block is combined with each of the b blocks, to form
    // one new complete block (which is hashed), and one new trailing block
    let DynamicBlock = DynamicArray(UInt8, { maxLength: CHARS_PER_BLOCK });
    let trailingLength = aTrailingBlock.length;

    let { hash, trailing } = bBlocks.reduce(
      { hash: Field, trailing: DynamicBlock },
      { hash: aHash, trailing: aTrailingBlock },
      (acc, bBlock) => {
        let combined = acc.trailing.concatTransposed(bBlock);
        let completeHalf = combined.array.slice(0, CHARS_PER_BLOCK);
        let trailingHalf = combined.array.slice(CHARS_PER_BLOCK);

        let hash = Poseidon.hash([acc.hash, packBytes(completeHalf)]);
        let trailing = new DynamicBlock(trailingHalf, trailingLength);
        return { hash, trailing };
      }
    );

    // the trailing block of the second string is combined with the final trailing block
    let combined = trailing.concatTransposed(bTrailingBlock);
    combined.normalize(); // needed to not hash non-zero padding bytes
    let firstHalf = combined.array.slice(0, CHARS_PER_BLOCK);
    let secondHalf = combined.array.slice(CHARS_PER_BLOCK);

    // we hash the first half if is the combined length is greater than zero,
    // and also the second half if the combined length is greater than the block size
    hash = Provable.if(
      combined.length.equals(0),
      hash,
      Poseidon.hash([hash, packBytes(firstHalf)])
    );
    hash = Provable.if(
      UInt32.Unsafe.fromField(combined.length).lessThanOrEqual(
        UInt32.from(CHARS_PER_BLOCK)
      ),
      hash,
      Poseidon.hash([hash, packBytes(secondHalf)])
    );

    // the `hash` we have computed is a uniquely identifying fingerprint of the concatenated strings
    // therefore, we can simply witness the combined string and check that the hash matches

    // witness combined string
    let Combined = DynamicString({
      maxLength: this.maxLength + other.maxLength,
    });
    let ab = Provable.witness(
      Combined,
      () => this.toString() + other.toString()
    );
    // chunk combined string into blocks of CHARS_PER_BLOCK, and hash them in the same way
    let [abBlocks, abTrailing] = ab.chunk(CHARS_PER_BLOCK);
    let abHash = abBlocks.reduce(Field, Field(0), (hash, block) =>
      Poseidon.hash([hash, packBytes(block.array)])
    );
    abHash = Provable.if(
      abTrailing.length.equals(0),
      abHash,
      Poseidon.hash([abHash, packBytes(abTrailing.array)])
    );
    // assert that the hashes match
    hash.assertEquals(abHash, 'failed to concatenate strings');
    // assert that the lengths match (implicitly proven by the hash as well)
    ab.length.assertEquals(this.length.add(other.length));

    return ab;
  }

  /**
   * Assert that this string is equal to another.
   *
   * Note: This only requires the length and the actual elements to be equal, not the padding or the maxLength.
   * To check for exact equality, use `assertEqualsStrict()`.
   */
  assertEquals(
    // complicated type here because we have to extend the method signature on DynamicArrayBase
    other:
      | DynamicString
      | DynamicArray<UInt8, UInt8V>
      | StaticArray<UInt8, UInt8V>
      | (UInt8 | UInt8V)[]
      | string
  ) {
    if (typeof other === 'string') {
      other = DynamicString({ maxLength: stringLength(other) }).from(other);
    }
    super.assertEquals(other);
  }

  splitAt(index: number): [DynamicString, DynamicString] {
    let [a, b] = super.splitAt(index);
    let StringA = DynamicString({ maxLength: a.maxLength });
    let StringB = DynamicString({ maxLength: b.maxLength });
    return [new StringA(a.array, a.length), new StringB(b.array, b.length)];
  }

  slice(start: number | UInt32) {
    let slice = super.slice(start);
    let String = DynamicString({ maxLength: this.maxLength });
    return new String(slice.array, slice.length);
  }

  reverse() {
    let reversed = super.reverse();
    let String = DynamicString({ maxLength: this.maxLength });
    return new String(reversed.array, reversed.length);
  }

  assertContains(
    substring:
      | StaticArray<UInt8, UInt8V>
      | DynamicArray<UInt8, UInt8V>
      | string,
    message?: string
  ): Field {
    if (typeof substring === 'string') {
      substring = DynamicString.from(substring);
    }
    return super.assertContains(substring, message);
  }

  growMaxLengthTo(maxLength: number): DynamicStringBase {
    assert(
      maxLength >= this.maxLength,
      'new maxLength must be greater or equal'
    );
    let array = pad(this.array, maxLength, UInt8.from(0));
    return new (DynamicString({ maxLength }))(array, this.length);
  }
}

DynamicString.Base = DynamicStringBase;

type UInt8V = { value: bigint };

// serialize/deserialize

ProvableFactory.register(DynamicString, {
  typeToJSON(constructor) {
    return { maxLength: constructor.maxLength };
  },

  typeFromJSON(json) {
    return DynamicString({ maxLength: json.maxLength });
  },

  valueToJSON(_, value) {
    return value.toString();
  },

  valueFromJSON(type, value) {
    return type.from(value);
  },
});
