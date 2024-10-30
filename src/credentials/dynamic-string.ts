import { Bool, Bytes, Field, Provable, UInt8 } from 'o1js';
import { DynamicArrayBase, provableDynamicArray } from './dynamic-array.ts';
import { ProvableFactory } from '../provable-factory.ts';
import { assert } from '../util.ts';

export { DynamicString };

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

  class DynamicString extends DynamicBytesBase {
    static get maxLength() {
      return maxLength;
    }
    static get provable() {
      return provableArray;
    }

    /**
     * Create DynamicBytes from a byte array in various forms.
     */
    static fromBytes(bytes: Uint8Array | (number | bigint | UInt8)[] | Bytes) {
      if (bytes instanceof Bytes.Base) bytes = bytes.bytes;
      return provableArray.fromValue(
        [...bytes].map((t) => UInt8.from(t)) as any
      );
    }

    /**
     * Create DynamicBytes from a string.
     */
    static from(s: string) {
      return DynamicString.fromBytes(new TextEncoder().encode(s));
    }

    /**
     * Convert DynamicBytes to a byte array.
     */
    static toBytes(bytes: DynamicString) {
      return new Uint8Array(bytes.toValue().map(({ value }) => Number(value)));
    }

    /**
     * Convert DynamicBytes to a string.
     */
    static toString(bytes: DynamicString) {
      return new TextDecoder().decode(DynamicString.toBytes(bytes));
    }
  }

  const provableArray = provableDynamicArray<UInt8, { value: bigint }>(
    UInt8 as any,
    DynamicString
  );

  return DynamicString;
}

class DynamicBytesBase extends DynamicArrayBase<UInt8, { value: bigint }> {
  get innerType() {
    return UInt8 as any as Provable<UInt8, { value: bigint }>;
  }
}

DynamicString.Base = DynamicBytesBase;

// serialize/deserialize

ProvableFactory.register(DynamicString, {
  typeToJSON(constructor) {
    return { maxLength: constructor.maxLength };
  },

  typeFromJSON(json) {
    return DynamicString({ maxLength: json.maxLength });
  },

  valueToJSON(type, value) {
    return type.toString(value);
  },

  valueFromJSON(type, value) {
    return type.from(value);
  },
});
