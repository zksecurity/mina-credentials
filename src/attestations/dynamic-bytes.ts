import { Bool, Field, Provable, ProvablePure, Struct, UInt8 } from 'o1js';
import { assert } from '../util.ts';

export { DynamicBytes };

type InputBytes = (UInt8 | bigint | number)[] | Uint8Array;
type DynamicBytes = DynamicBytesBase;

/**
 * Dynamic-length bytes type that has a
 * - constant max length, but
 * - dynamic actual length
 *
 * ```ts
 * const Bytes = DynamicBytes({ maxLength: 32 });
 * ```
 */
function DynamicBytes({
  maxLength,
}: {
  maxLength: number;
}): typeof DynamicBytesBase {
  class DynamicBytes extends DynamicBytesBase {
    static get maxLength() {
      return maxLength;
    }
    static get provable() {
      return provableBytes;
    }
  }
  const provableBytes = provable(DynamicBytes);

  return DynamicBytes;
}

let NULL = UInt8.from(0);

class DynamicBytesBase {
  bytes: UInt8[];
  length: Field;

  // prop to override
  static get maxLength(): number {
    throw Error('Max length must be defined in a subclass.');
  }

  // derived props
  get maxLength(): number {
    return (this.constructor as typeof DynamicBytesBase).maxLength;
  }
  static get provable() {
    return provable(this);
  }

  constructor(input: InputBytes, length: Field) {
    let maxLength = this.maxLength;

    assert(input.length <= maxLength, 'input too long');

    let bytes = Array.from({ length: maxLength }, () => NULL);

    for (let i = 0; i < input.length; i++) {
      bytes[i] = UInt8.from(input[i]!);
    }

    this.bytes = bytes;
    this.length = length;
  }

  static from(input: InputBytes | DynamicBytesBase) {
    if (input instanceof DynamicBytesBase) return input;
    let length = Provable.witness(Field, () => input.length);
    let bytes = new this(input, length);
    bytes._verifyLength();
    return bytes;
  }
  static fromStatic(input: InputBytes | DynamicBytesBase) {
    if (input instanceof DynamicBytesBase) return input;
    return new this(input, Field(input.length));
  }

  static fromString(s: string) {
    let bytes = new TextEncoder().encode(s);
    return this.from(bytes);
  }

  _verifyLength() {
    // - length must be <= maxLength
    // - every entry past `length` must be NULL
    let length = this.length;
    let pastLength = Bool(false);

    this.bytes.forEach((x, i) => {
      let isLength = length.equals(i);
      pastLength = pastLength.or(isLength);
      Provable.assertEqualIf(pastLength, UInt8, x, NULL);
    });
    let isLength = length.equals(this.maxLength + 1);
    pastLength.or(isLength).assertTrue();
  }
}

/**
 * Base class of all DynamicBytes subclasses
 */
DynamicBytes.Base = DynamicBytesBase;

// TODO make this easier by exporting provableFromClass from o1js

function provable(
  Class: typeof DynamicBytesBase
): ProvablePure<DynamicBytesBase, Uint8Array> {
  let maxLength = Class.maxLength;

  let PlainBytes = Struct({
    bytes: Provable.Array(UInt8, maxLength),
    length: Field,
  });
  return {
    ...PlainBytes,

    // make fromFields return a class instance
    fromFields(fields) {
      let raw = PlainBytes.fromFields(fields);
      return new Class(raw.bytes, raw.length);
    },

    // convert to/from Uint8Array
    toValue(value) {
      return new Uint8Array(value.bytes.map((x) => x.toNumber()));
    },
    fromValue(value) {
      if (value instanceof Uint8Array) {
        return new Class(value, Field(value.length));
      }
      assert(value instanceof Class, 'invalid input');
      return value;
    },

    // check has to validate length in addition to the other checks
    check(value) {
      PlainBytes.check(value);
      value._verifyLength();
    },
  };
}
