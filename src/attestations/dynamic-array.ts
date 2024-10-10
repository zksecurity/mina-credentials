import {
  Bool,
  Field,
  InferProvable,
  Option,
  Provable,
  Struct,
  UInt32,
} from 'o1js';
import { assert, zip } from '../util.ts';
import { ProvableType } from '../o1js-missing.ts';
import { InferValue } from 'o1js/dist/node/bindings/lib/provable-generic.js';
import { arrayGet } from 'o1js/dist/node/lib/provable/gadgets/basic.js';
import {
  assertInRange16,
  assertLessThan16,
  lessThan16,
  seal,
  unsafeIf,
} from './gadgets.ts';

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
  provable: Provable<DynamicArrayBase<T>, V[]>;

  from(v: (T | V)[]): DynamicArrayBase<T>;
} {
  let innerType: Provable<T, V> = ProvableType.get(type);

  // assert maxLength bounds
  assert(maxLength >= 0, 'maxLength must be >= 0');
  assert(maxLength < 2 ** 16, 'maxLength must be < 2^16');

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
      // length must be within maxLength
      assertInRange16(length, this.maxLength);

      return new this(values, length);
    }
  }
  const provableArray = provable<T, V>(innerType, DynamicArray);

  return DynamicArray;
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
    assert(input.length <= maxLength, 'input exceeds maxLength');

    let NULL = ProvableType.synthesize(this.innerType);
    let array = Array.from({ length: maxLength }, () => NULL);
    input.forEach((t, i) => {
      array[i] = t;
    });

    this.array = array;
    this.length = length;
  }

  // public methods

  /**
   * Asserts that 0 <= i < this.length, using a cached check that's not duplicated when doing it on the same variable multiple times.
   *
   * Cost: 1.5 constraints
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
   * Cost:
   * - 1.5N for the index mask
   * - TN for unsafeIf
   * - 2.5 for less than
   * = (1.5 + T)*N + 2.5
   */
  getOption(i: UInt32): Option<T> {
    // TODO Using a 16-bit less-than + getOrUnconstrained here would be more efficient for most array sizes
    let type = this.innerType;
    let value = ProvableType.synthesize(type);
    let equalsI = this._indexMask(i.value);
    let iContained = lessThan16(i.value, this.length);

    zip(this.array, equalsI).forEach(([t, equalsIJ]) => {
      value = unsafeIf(equalsIJ, type, value, t);
    });
    value = seal(type, value); // otherwise return value is a long AST
    const OptionT = Option(type);
    return OptionT.fromValue({ isSome: iContained, value });
  }

  /**
   * Gets a value at index i, ASSUMING that the index is in the array.
   *
   * If the index is in fact not in the array, the return value is completely unconstrained.
   *
   * **Warning**: Only use this if you already know/proved by other means that the index is within bounds.
   *
   * Cost: T*N
   */
  getOrUnconstrained(i: Field): T {
    let type = this.innerType;
    let ai = Provable.witness(type, () => this.array[Number(i)]);
    let aiFields = type.toFields(ai);

    // assert a is correct on every field column with arrayGet()
    let fields = this.array.map((t) => type.toFields(t));

    for (let j = 0; j < type.sizeInFields(); j++) {
      let column = fields.map((x) => x[j]!);
      arrayGet(column, i).assertEquals(aiFields[j]!);
    }
    return ai;
  }

  /**
   * Sets a value at index i and proves that the index is in the array.
   */
  set(i: UInt32, value: T): void {
    this.assertIndexInRange(i);
    this.setOrDoNothing(i.value, value);
  }

  /**
   * Sets a value at index i, or does nothing if the index is not in the array
   */
  setOrDoNothing(i: Field, value: T): void {
    zip(this.array, this._indexMask(i)).forEach(([t, equalsIJ], i) => {
      this.array[i] = Provable.if(equalsIJ, this.innerType, value, t);
    });
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

  // cached variables to not duplicate constraints if we do something like array.get(i), array.set(i, ..) on the same index
  _masks: Map<Field, Bool[]> = new Map();
  _indicesInRange: Set<Field> = new Set();

  /**
   * Compute i.equals(j) for all indices j in the static-size array.
   *
   * Costs: 1.5N
   * TODO: equals() could be optimized to just 1 double generic because j is constant, o1js doesn't do that
   */
  _indexMask(i: Field) {
    let mask = this._masks.get(i);
    mask ??= this.array.map((_, j) => i.equals(j));
    this._masks.set(i, mask);
    return mask;
  }
}

/**
 * Base class of all DynamicBytes subclasses
 */
DynamicArray.Base = DynamicArrayBase;

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
      assertInRange16(value.length, maxLength);
    },
  };
}
