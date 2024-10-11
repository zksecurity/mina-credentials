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
import { assert, chunk, pad, zip } from '../util.ts';
import { ProvableType } from '../o1js-missing.ts';
import { assertInRange16, assertLessThan16, lessThan16 } from './gadgets.ts';
import { StaticArray } from './static-array.ts';

export { DynamicArray };

type DynamicArray<T> = DynamicArrayBase<T>;

/**
 * Dynamic-length array type that has a
 * - constant max length, but
 * - dynamic actual length
 *
 * ```ts
 * const Bytes = DynamicArray(UInt8, { maxLength: 32 });
 * ```
 *
 * `maxLength` can be any number from 0 to 2^16-1.
 *
 * **Details**: Internally, this is represented as a static-sized array, plus a Field element
 * that represents the length.
 * The _only_ requirement on these is that the length is less or equal maxLength.
 * In particular, there are no provable guarantees maintained on the content of the static-sized array beyond the actual length.
 * Instead, our methods ensure integrity of array operations _within_ the actual length.
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
  provable: ProvableHashable<DynamicArrayBase<T>, V[]>;

  /**
   * Create a new DynamicArray from an array of values.
   *
   * Note: Both the actual length and the values beyond the original ones will be constant.
   */
  from(v: (T | V)[]): DynamicArrayBase<T>;
} {
  let innerType: Provable<T, V> = ProvableType.get(type);

  // assert maxLength bounds
  assert(maxLength >= 0, 'maxLength must be >= 0');
  assert(maxLength < 2 ** 16, 'maxLength must be < 2^16');

  class DynamicArray_ extends DynamicArrayBase<T> {
    get innerType() {
      return innerType;
    }
    static get maxLength() {
      return maxLength;
    }
    static get provable() {
      return provableArray;
    }

    static from(input: (T | V)[] | DynamicArrayBase<T>) {
      return provableArray.fromValue(input);
    }
  }
  const provableArray = provable<T, V>(innerType, DynamicArray_);

  return DynamicArray_;
}

class DynamicArrayBase<T = any> {
  /**
   * The internal array, which includes the actual values, padded up to `maxLength` with unconstrained values.
   */
  array: T[];

  /**
   * Length of the array. Guaranteed to be in [0, maxLength].
   */
  length: Field;

  // props to override
  get innerType(): Provable<T> {
    throw Error('Inner type must be defined in a subclass.');
  }
  static get maxLength(): number {
    throw Error('Max length must be defined in a subclass.');
  }

  // derived prop
  get maxLength(): number {
    return (this.constructor as typeof DynamicArrayBase).maxLength;
  }

  constructor(array: T[], length: Field) {
    let maxLength = this.maxLength;
    assert(array.length === maxLength, 'input has to match maxLength');
    this.array = array;
    this.length = length;
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
   *
   * **Warning**: The callback will be passed unconstrained dummy values.
   */
  map<S>(type: ProvableType<S>, f: (t: T) => S): DynamicArray<S> {
    let Array = DynamicArray(type, { maxLength: this.maxLength });
    let array = this.array.map(f);
    let newArray = new Array(array, this.length);

    // new array has same length/maxLength, so it can use the same cached masks
    newArray._indexMasks = this._indexMasks;
    newArray._indicesInRange = this._indicesInRange;
    newArray.__dummyMask = this.__dummyMask;
    return newArray;
  }

  /**
   * Iterate over all elements of the array.
   *
   * The callback will be passed an element and a boolean `isDummy` indicating whether the value is part of the actual array.
   */
  forEach(f: (t: T, isDummy: Bool) => void) {
    zip(this.array, this._dummyMask()).forEach(([t, isDummy]) => {
      f(t, isDummy);
    });
  }

  /**
   * Reduce the array to a single value.
   *
   * The callback will be passed the current state, an element, and a boolean `isDummy` indicating whether the value is part of the actual array.
   */
  reduce<S>(
    stateType: ProvableType<S>,
    state: S,
    f: (state: S, t: T, isDummy: Bool) => S
  ): S {
    this.forEach((t, isDummy) => {
      let newState = f(state, t, isDummy);
      state = Provable.if(isDummy, stateType, state, newState);
    });
    return state;
  }

  /**
   * Push a value, without changing the maxLength.
   *
   * Proves that the new length is still within the maxLength, fails otherwise.
   *
   * To grow the maxLength along with the actual length, you can use:
   *
   * ```ts
   * array = array.growMaxLengthBy(1);
   * array.push(value);
   * ```
   *
   * Cost: 1.5(T + 1)N + 2
   */
  push(value: T): void {
    let oldLength = this.length;
    this.length = oldLength.add(1).seal();
    assertInRange16(this.length, this.maxLength);
    this.setOrDoNothing(oldLength, value);
  }

  /**
   * Return a version of the same array with a larger maxLength.
   *
   * **Warning**: Does not modify the array, but returns a new one.
   *
   * **Note**: this doesn't cost constraints, but currently doesn't preserve any cached constraints.
   */
  growMaxLengthTo(maxLength: number): DynamicArray<T> {
    assert(
      maxLength >= this.maxLength,
      'new maxLength must be greater or equal'
    );
    let NewArray = DynamicArray(this.innerType, { maxLength });
    let NULL = ProvableType.synthesize(this.innerType);
    let array = pad(this.array, maxLength, NULL);
    let length = this.length;
    return new NewArray(array, length);
  }

  /**
   * Return a version of the same array with a larger maxLength.
   *
   * **Warning**: Does not modify the array, but returns a new one.
   *
   * **Note**: this doesn't cost constraints, but currently doesn't preserve any cached constraints.
   */
  growMaxLengthBy(maxLength: number): DynamicArray<T> {
    return this.growMaxLengthTo(this.maxLength + maxLength);
  }

  /**
   * Split into a (dynamic) number of fixed-size chunks.
   * Does not assume that the max length or actual length are multiples of the chunk size.
   *
   * Warning: The last chunk will contain dummy values if the actual length is not a multiple of the chunk size.
   */
  chunk(chunkSize: number) {
    assert(chunkSize < 2 ** 16, 'chunkSize must be < 2^16');
    let NULL = ProvableType.synthesize(this.innerType);
    let newMaxLength = Math.ceil(this.maxLength / chunkSize);
    let padded = pad(this.array, newMaxLength * chunkSize, NULL);
    let chunked = chunk(padded, chunkSize);
    // new length = Math.ceil(this.length / chunkSize)
    let { quotient: newLength, rest } = UInt32.Unsafe.fromField(
      this.length.add(chunkSize - 1)
    ).divMod(chunkSize);

    const Chunk = StaticArray(this.innerType, chunkSize);
    const Chunked = DynamicArray(Chunk, { maxLength: newMaxLength });
    return {
      chunks: new Chunked(chunked.map(Chunk.from), newLength.value),
      innerLength: rest.value,
    };
  }

  // cached variables to not duplicate constraints if we do something like array.get(i), array.set(i, ..) on the same index
  _indexMasks: Map<Field, Bool[]> = new Map();
  _indicesInRange: Set<Field> = new Set();
  __dummyMask?: Bool[];

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

  /**
   * Tells us which elements are dummies = not actually in the array.
   *
   * 0 0 0 1 1 1 1
   *       ^
   *       length
   */
  _dummyMask() {
    if (this.__dummyMask !== undefined) return this.__dummyMask;
    let isLength = this._indexMask(this.length);
    let wasLength = Bool(false);

    let mask = isLength.map((isLength) => {
      wasLength = wasLength.or(isLength);
      return wasLength;
    });
    this.__dummyMask = mask;
    return mask;
  }
}

/**
 * Base class of all DynamicArray subclasses
 */
DynamicArray.Base = DynamicArrayBase;

function provable<T, V>(
  type: Provable<T, V>,
  Class: typeof DynamicArrayBase<T>
): ProvableHashable<DynamicArrayBase<T>, V[]> {
  let maxLength = Class.maxLength;
  let NULL = ProvableType.synthesize(type);

  let PlainArray = struct({
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

    // convert to/from plain array that has the correct length
    toValue(value) {
      let length = Number(value.length);
      return value.array.map((t) => type.toValue(t)).slice(0, length);
    },
    fromValue(value) {
      if (value instanceof DynamicArrayBase) return value;
      let array = value.map((t) => type.fromValue(t));
      let padded = pad(array, maxLength, NULL);
      return new Class(padded, Field(value.length));
    },

    // check has to validate length in addition to the other checks
    check(value) {
      PlainArray.check(value);
      assertInRange16(value.length, maxLength);
    },

    empty() {
      let raw = PlainArray.empty();
      return new Class(raw.array, raw.length);
    },
  };
}
