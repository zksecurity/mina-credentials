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
  return class DynamicBytes extends DynamicBytesBase {
    static get maxLength() {
      return maxLength;
    }

    static get provable() {
      return provable(this, maxLength);
    }
  };
}

type PlainDynamicBytes = { bytes: UInt8[]; length: Field };

let NULL = UInt8.from(0);

class DynamicBytesBase {
  bytes: UInt8[];
  length: Field;

  // props to override
  static get maxLength(): number {
    throw Error('Max length must be defined in a subclass.');
  }
  static get provable(): ProvablePure<DynamicBytesBase, Uint8Array> {
    throw Error('.provable is defined on subclass.');
  }

  // derived prop
  get maxLength(): number {
    return (this.constructor as typeof DynamicBytesBase).maxLength;
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
    this._verifyLength(bytes, bytes.maxLength);
    return bytes;
  }
  static fromStatic(input: InputBytes | DynamicBytesBase) {
    if (input instanceof DynamicBytesBase) return input;
    return new this(input, Field(input.length));
  }

  static _verifyLength(self: PlainDynamicBytes, maxLength: number) {
    assert(self.bytes.length <= maxLength);

    // - length must be <= maxLength
    // - every entry past `length` must be NULL
    let length = self.length;
    let pastLength = Bool(false);

    self.bytes.forEach((x, i) => {
      let isLength = length.equals(i);
      pastLength = pastLength.or(isLength);
      Provable.assertEqualIf(pastLength, UInt8, x, NULL);
    });
    let isLength = length.equals(maxLength + 1);
    pastLength.or(isLength).assertTrue();
  }
}

/**
 * Base class of all DynamicBytes subclasses
 */
DynamicBytes.Base = DynamicBytesBase;

// TODO make this easier by exporting provableFromClass from o1js

function provable<T extends DynamicBytesBase>(
  Class: Constructor<T>,
  maxLength: number
): ProvablePure<T, Uint8Array> {
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

    // check has to validate length
    check(value) {
      DynamicBytesBase._verifyLength(value, maxLength);
    },
  };
}

type Constructor<T> = new (...args: any) => T;
