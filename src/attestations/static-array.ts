import {
  Bool,
  Field,
  type InferProvable,
  Option,
  Provable,
  provable as struct,
  UInt32,
  type InferValue,
  Gadgets,
  type ProvableHashable,
} from 'o1js';
import { assert, chunk, zip } from '../util.ts';
import { ProvableType } from '../o1js-missing.ts';
import { assertLessThan16, lessThan16 } from './gadgets.ts';

export { StaticArray };

type StaticArray<T> = StaticArrayBase<T>;

/**
 * Array with a fixed number of elements and several helper methods.
 *
 * ```ts
 * const Bytes32 = StaticArray(UInt8, 32);
 * ```
 *
 * The second parameter is the `length`. It can be any number from 0 to 2^16-1.
 */
function StaticArray<
  A extends ProvableType,
  T extends InferProvable<A> = InferProvable<A>,
  V extends InferValue<A> = InferValue<A>
>(
  type: A,
  length: number
): typeof StaticArrayBase<T> & {
  provable: ProvableHashable<StaticArrayBase<T>, V[]>;

  /**
   * Create a new StaticArray from a raw array of values.
   */
  from(v: (T | V)[] | StaticArrayBase<T>): StaticArrayBase<T>;
} {
  let innerType: Provable<T, V> = ProvableType.get(type);

  // assert length bounds
  assert(length >= 0, 'length must be >= 0');
  assert(length < 2 ** 16, 'length must be < 2^16');

  class StaticArray_ extends StaticArrayBase<T> {
    get innerType() {
      return innerType;
    }
    static get length() {
      return length;
    }
    static get provable() {
      return provableArray;
    }

    static from(input: (T | V)[] | StaticArrayBase<T>) {
      return provableArray.fromValue(input);
    }
  }
  const provableArray = provable<T, V>(innerType, StaticArray_);

  return StaticArray_;
}

class StaticArrayBase<T = any> {
  /**
   * The plain array
   */
  array: T[];

  // props to override
  get innerType(): Provable<T> {
    throw Error('Inner type must be defined in a subclass.');
  }
  static get length(): number {
    throw Error('Length must be defined in a subclass.');
  }

  // derived prop
  get length(): number {
    return (this.constructor as typeof StaticArrayBase).length;
  }

  constructor(array: T[]) {
    assert(array.length === this.length, 'input has to match length');
    this.array = array;
  }

  /**
   * Asserts that 0 <= i < this.length, using a cached check that's not duplicated when doing it on the same variable multiple times.
   *
   * Cost: 1.5
   */
  assertIndexInRange(i: UInt32) {
    if (!this._indicesInRange.has(i.value)) {
      assertLessThan16(i, this.length);
      this._indicesInRange.add(i.value);
    }
  }

  /**
   * Gets value at index i, and proves that the index is in the array.
   *
   * Cost: TN + 1.5
   */
  get(i: UInt32): T {
    this.assertIndexInRange(i);
    return this.getOrUnconstrained(i.value);
  }

  /**
   * Gets a value at index i, as an option that is None if the index is not in the array.
   *
   * Note: The correct type for `i` is actually UInt16 which doesn't exist. The method is not complete (but sound) for i >= 2^16.
   *
   * Cost: TN + 2.5
   */
  getOption(i: UInt32): Option<T> {
    let type = this.innerType;
    let isContained = lessThan16(i.value, this.length);
    let value = this.getOrUnconstrained(i.value);
    const OptionT = Option(type);
    return OptionT.fromValue({ isSome: isContained, value });
  }

  /**
   * Gets a value at index i, ASSUMING that the index is in the array.
   *
   * If the index is in fact not in the array, the return value is completely unconstrained.
   *
   * **Warning**: Only use this if you already know/proved by other means that the index is within bounds.
   *
   * Cost: T*N where T = size of the type
   */
  getOrUnconstrained(i: Field): T {
    let type = this.innerType;
    let ai = Provable.witness(type, () => this.array[Number(i)]);
    let aiFields = type.toFields(ai);

    // assert a is correct on every field column with arrayGet()
    let fields = this.array.map((t) => type.toFields(t));

    for (let j = 0; j < type.sizeInFields(); j++) {
      let column = fields.map((x) => x[j]!);
      Gadgets.arrayGet(column, i).assertEquals(aiFields[j]!);
    }
    return ai;
  }

  /**
   * Sets a value at index i and proves that the index is in the array.
   *
   * Cost: 1.5(T + 1)N + 1.5
   */
  set(i: UInt32, value: T): void {
    this.assertIndexInRange(i);
    this.setOrDoNothing(i.value, value);
  }

  /**
   * Sets a value at index i, or does nothing if the index is not in the array
   *
   * Cost: 1.5(T + 1)N
   */
  setOrDoNothing(i: Field, value: T): void {
    zip(this.array, this._indexMask(i)).forEach(([t, equalsIJ], i) => {
      this.array[i] = Provable.if(equalsIJ, this.innerType, value, t);
    });
  }

  /**
   * Map every element of the array to a new value.
   */
  map<S>(type: ProvableType<S>, f: (t: T) => S): StaticArray<S> {
    let NewArray = StaticArray(type, this.length);
    let array = this.array.map(f);
    let newArray = new NewArray(array);

    // new array has same length, so it can use the same cached masks
    newArray._indexMasks = this._indexMasks;
    newArray._indicesInRange = this._indicesInRange;
    return newArray;
  }

  /**
   * Iterate over all elements of the array.
   */
  forEach(f: (t: T) => void) {
    this.array.forEach(f);
  }

  /**
   * Reduce the array to a single value.
   */
  reduce<S>(state: S, f: (state: S, t: T) => S): S {
    this.forEach((t) => {
      state = f(state, t);
    });
    return state;
  }

  /**
   * Split into a static number of fixed-size chunks.
   * Requires that the length is a multiple of the chunk size.
   */
  chunk(chunkSize: number) {
    let chunked = chunk(this.array, chunkSize);
    let newLength = this.length / chunkSize;
    const Chunk = StaticArray(this.innerType, chunkSize);
    const Chunked = StaticArray(Chunk, newLength);
    return new Chunked(chunked.map(Chunk.from));
  }

  // cached variables to not duplicate constraints if we do something like array.get(i), array.set(i, ..) on the same index
  _indexMasks: Map<Field, Bool[]> = new Map();
  _indicesInRange: Set<Field> = new Set();

  /**
   * Compute i.equals(j) for all indices j in the static-size array.
   *
   * Costs: 1.5N
   *
   * TODO: equals() could be optimized to just 1 double generic because j is constant, o1js doesn't do that
   */
  _indexMask(i: Field) {
    let mask = this._indexMasks.get(i);
    mask ??= this.array.map((_, j) => i.equals(j));
    this._indexMasks.set(i, mask);
    return mask;
  }
}

/**
 * Base class of all StaticArray subclasses
 */
StaticArray.Base = StaticArrayBase;

function provable<T, V>(
  type: Provable<T, V> & { empty?: () => T },
  Class: typeof StaticArrayBase<T>
): ProvableHashable<StaticArrayBase<T>, V[]> {
  let maxLength = Class.length;
  let PlainArray = struct({ array: Provable.Array(type, maxLength) });

  return {
    ...PlainArray,

    // make fromFields return a class instance
    fromFields(fields, aux) {
      let raw = PlainArray.fromFields(fields, aux);
      return new Class(raw.array);
    },

    // convert to/from plain array
    toValue(value) {
      return PlainArray.toValue(value).array;
    },
    fromValue(array) {
      if (array instanceof StaticArrayBase) return array;
      let raw = PlainArray.fromValue({ array });
      return new Class(raw.array);
    },

    empty() {
      let raw = PlainArray.empty();
      return new Class(raw.array);
    },
  };
}
