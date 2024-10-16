import { Bool, Bytes, Field, UInt8 } from 'o1js';
import { DynamicArray } from './dynamic-array.ts';

export { DynamicBytes };

/**
 * Specialization of `DynamicArray` to bytes,
 * with added helper methods to create instances.
 *
 * ```ts
 * const Bytes = DynamicBytes({ maxLength: 120 });
 *
 * let bytes = Bytes.fromString('hello');
 * let bytes2 = Bytes.fromBytes([1, 2, 3]);
 * ```
 */
function DynamicBytes({ maxLength }: { maxLength: number }) {
  return class DynamicBytes extends DynamicArray(UInt8, { maxLength }) {
    /**
     * Create DynamicBytes from a byte array in various forms.
     */
    static fromBytes(bytes: Uint8Array | (number | bigint | UInt8)[] | Bytes) {
      if (bytes instanceof Bytes.Base) bytes = bytes.bytes;
      return DynamicBytes.from([...bytes].map((t) => UInt8.from(t)));
    }

    /**
     * Create DynamicBytes from a string.
     */
    static fromString(s: string) {
      return DynamicBytes.fromBytes(new TextEncoder().encode(s));
    }
  };
}
