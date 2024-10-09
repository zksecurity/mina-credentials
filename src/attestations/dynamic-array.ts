import { Bool, Field, InferProvable, Provable, Struct } from 'o1js';
import { assert } from '../util.ts';
import { ProvableType } from '../o1js-missing.ts';
import { InferValue } from 'o1js/dist/node/bindings/lib/provable-generic.js';

export { DynamicArray };

type DynamicArray<T> = DynamicArrayBase<T>;

/**
 * Dynamic-length bytes type that has a
 * - constant max length, but
 * - dynamic actual length
 *
 * ```ts
 * const Bytes = DynamicArray(UInt8, { maxLength: 32 });
 * ```
 *
 * **Details**: Internally, this is represented as a static-sized array, plus a Field element
 * that represents the length.
 * The only requirement on these is that the length has to be smaller than the maxLength.
 * In particular, there are no provable guarantees maintained on the content of the
 * static-sized array beyond the actual length.
 */
function DynamicArray<
  A extends ProvableType,
  T extends InferProvable<A> = InferProvable<A>,
  V extends InferValue<A> = InferValue<A>
>(
  type: A,
  {
    maxLength,
  }: {
    maxLength: number;
  }
): typeof DynamicArrayBase<T> & {
  provable: Provable<DynamicArrayBase<T>, V[]>;

  from(v: (T | V)[]): DynamicArrayBase<T>;
} {
  let innerType: Provable<T, V> = ProvableType.get(type);

  class DynamicArray extends DynamicArrayBase<T> {
    get innerType() {
      return innerType;
    }
    static get maxLength() {
      return maxLength;
    }
    static get provable(): Provable<DynamicArrayBase<T>, V[]> {
      return provableArray;
    }

    static from(input: (T | V)[] | DynamicArrayBase) {
      if (input instanceof DynamicArrayBase) return input;
      let values = input.map((t) => innerType.fromValue(t));
      let length = Provable.witness(Field, () => input.length);
      let bytes = new this(values, length);
      bytes._verifyLength();
      return bytes;
    }
  }
  const provableArray = provable<T, V>(innerType, DynamicArray);

  return DynamicArray;
}

class DynamicArrayBase<T = any> {
  array: T[];
  length: Field;

  // prop to override
  static get maxLength(): number {
    throw Error('Max length must be defined in a subclass.');
  }
  get innerType(): Provable<T> {
    throw Error('Inner type must be defined in a subclass.');
  }

  // derived props
  get maxLength(): number {
    return (this.constructor as typeof DynamicArrayBase).maxLength;
  }
  static get provable(): Provable<any> {
    return provable(this.prototype.innerType, this);
  }

  constructor(input: T[], length: Field) {
    let maxLength = this.maxLength;

    assert(input.length <= maxLength, 'input too long');

    let NULL = ProvableType.synthesize(this.innerType);
    let bytes = Array.from({ length: maxLength }, () => NULL);
    input.forEach((t, i) => {
      bytes[i] = t;
    });

    this.array = bytes;
    this.length = length;
  }

  // public methods

  /**
   * Gets a value at index i and proves that the index is in the array.
   */
  get(i: Field): T {
    throw Error('todo');
  }

  /**
   * Gets a value at index i, or a dummy value if the index is not in the array
   */
  getOrDummy(i: Field): T {
    throw Error('todo');
  }

  /**
   * Gets a value at index i, ASSUMING that the index is in the array.
   *
   * If the index is in fact not in the array, the return value is completely unconstrained.
   *
   * **Warning**: Only use this if you already know/proved by other means that the index is within bounds.
   */
  getOrUnconstrained(i: Field): T {
    throw Error('todo');
  }

  /**
   * Sets a value at index i and proves that the index is in the array.
   */
  set(i: Field, value: T): void {
    throw Error('todo');
  }

  /**
   * Sets a value at index i, or does nothing if the index is not in the array
   */
  setOrDoNothing(i: Field, value: T): void {
    throw Error('todo');
  }

  map<S>(type: Provable<S>, f: (t: T) => S): DynamicArray<S> {
    let Array = DynamicArray(type, { maxLength: this.maxLength });
    let array = this.array.map(f);
    return new Array(array, this.length);
  }

  forEach(f: (t: T, isDummy: Bool) => void) {
    throw Error('todo');
  }

  reduce<S>(
    stateType: Provable<S>,
    state: S,
    f: (state: S, t: T, isDummy: Bool) => T
  ): S {
    throw Error('todo');
  }

  /**
   * Split into a (dynamic) number of fixed-size chunks
   */
  chunk(chunkSize: number): DynamicArray<T[]> {
    throw Error('todo');
  }

  _verifyLength() {
    // - length must be <= maxLength
    // - every entry past `length` must be NULL
    let length = this.length;
    let pastLength = Bool(false);

    this.array.forEach((x, i) => {
      let isLength = length.equals(i);
      pastLength = pastLength.or(isLength);
      let NULL = ProvableType.synthesize(this.innerType);
      Provable.assertEqualIf(pastLength, this.innerType, x, NULL);
    });
    let isLength = length.equals(this.maxLength + 1);
    pastLength.or(isLength).assertTrue();
  }
}

/**
 * Base class of all DynamicBytes subclasses
 */
DynamicArray.Base = DynamicArrayBase;

// TODO make this easier by exporting provableFromClass from o1js

function provable<T, V>(
  type: Provable<T, V>,
  Class: typeof DynamicArrayBase<T>
): Provable<DynamicArrayBase<T>, V[]> {
  let maxLength = Class.maxLength;

  let PlainArray = Struct({
    array: Provable.Array(type, maxLength),
    length: Field,
  });
  return {
    ...PlainArray,

    // make fromFields return a class instance
    fromFields(fields, aux) {
      let raw = PlainArray.fromFields(fields, aux);
      return new Class(raw.array, raw.length);
    },

    // convert to/from Uint8Array
    toValue(value) {
      return value.array.map((t) => type.toValue(t));
    },
    fromValue(value) {
      if (value instanceof DynamicArrayBase) return value;
      let array = value.map((v) => type.fromValue(v));
      return new Class(array, Field(array.length));
    },

    // check has to validate length in addition to the other checks
    check(value) {
      PlainArray.check(value);
      value._verifyLength();
    },
  };
}
