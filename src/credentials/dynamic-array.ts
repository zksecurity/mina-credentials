import {
  Bool,
  Field,
  type InferProvable,
  Option,
  Provable,
  UInt32,
  type InferValue,
  Gadgets,
  type ProvableHashable,
  type From,
  type ProvablePure,
  type IsPure,
  Poseidon,
} from 'o1js';
import { assert, assertHasProperty, chunk, fill, pad, zip } from '../util.ts';
import {
  HashInput,
  type ProvableHashablePure,
  type ProvableHashableType,
  ProvableType,
} from '../o1js-missing.ts';
import {
  assertInRange16,
  assertLessThan16,
  lessThan16,
  pack,
} from './gadgets.ts';
import { ProvableFactory } from '../provable-factory.ts';
import {
  deserializeProvable,
  deserializeProvableType,
  serializeProvable,
  serializeProvableType,
} from '../serialize-provable.ts';
import { TypeBuilder, TypeBuilderPure } from '../provable-type-builder.ts';
import { StaticArray } from './static-array.ts';
import { bitSize, packedFieldSize, packToField } from './dynamic-hash.ts';

export { DynamicArray };

export { DynamicArrayBase, provable as provableDynamicArray };

type DynamicArray<T = any, V = any> = DynamicArrayBase<T, V>;

type DynamicArrayClass<T, V> = typeof DynamicArrayBase<T, V> & {
  provable: ProvableHashable<DynamicArrayBase<T, V>, V[]>;

  /**
   * Create a new DynamicArray from an array of values.
   *
   * Note: Both the actual length and the values beyond the original ones will be constant.
   */
  from(v: (T | V)[] | DynamicArrayBase<T, V>): DynamicArrayBase<T, V>;
};

type DynamicArrayClassPure<T, V> = typeof DynamicArrayBase<T, V> &
  Omit<DynamicArrayClass<T, V>, 'provable'> & {
    provable: ProvableHashable<DynamicArrayBase<T, V>, V[]> &
      ProvablePure<DynamicArrayBase<T, V>, V[]>;
  };

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
  A extends ProvableHashableType,
  T extends InferProvable<A> = InferProvable<A>,
  V extends InferValue<A> = InferValue<A>
>(
  type: A,
  options: { maxLength: number }
): IsPure<A, Field> extends true
  ? DynamicArrayClassPure<T, V>
  : DynamicArrayClass<T, V>;

function DynamicArray<
  A extends ProvableHashableType,
  T extends InferProvable<A> = InferProvable<A>,
  V extends InferValue<A> = InferValue<A>
>(
  type: A,
  {
    maxLength,
  }: {
    maxLength: number;
  }
): DynamicArrayClass<T, V> {
  // assert maxLength bounds
  assert(maxLength >= 0, 'maxLength must be >= 0');
  assert(maxLength < 2 ** 16, 'maxLength must be < 2^16');

  class DynamicArray_ extends DynamicArrayBase<T, V> {
    get innerType() {
      return type;
    }
    static get maxLength() {
      return maxLength;
    }
    static get provable() {
      return provableArray;
    }

    static from(input: (T | V)[] | DynamicArrayBase<T, V>) {
      return provableArray.fromValue(input);
    }
  }
  const provableArray = provable<T, V, typeof DynamicArrayBase<T, V>>(
    ProvableType.get(type),
    DynamicArray_
  ).build();

  return DynamicArray_;
}

class DynamicArrayBase<T = any, V = any> {
  /**
   * The internal array, which includes the actual values, padded up to `maxLength` with unconstrained values.
   */
  array: T[];

  /**
   * Length of the array. Guaranteed to be in [0, maxLength].
   */
  length: Field;

  // props to override
  get innerType(): ProvableHashableType<T, V> {
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
    let type = ProvableType.get(this.innerType);
    let NULL = ProvableType.synthesize(type);
    let ai = Provable.witness(type, () => this.array[Number(i)] ?? NULL);
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
    zip(this.array, this._indexMask(i)).forEach(([t, equalsIJ], j) => {
      this.array[j] = Provable.if(equalsIJ, this.innerType, value, t);
    });
  }

  /**
   * Map every element of the array to a new value.
   *
   * **Warning**: The callback will be passed unconstrained dummy values.
   */
  map<S extends ProvableHashableType>(
    type: S,
    f: (t: T, i: number) => From<S>
  ): DynamicArray<InferProvable<S>, InferValue<S>> {
    let Array = DynamicArray(type, { maxLength: this.maxLength });
    let provable = ProvableType.get(type);
    let array = this.array.map((x, i) => provable.fromValue(f(x, i)));
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
  forEach(f: (t: T, isDummy: Bool, i: number) => void) {
    zip(this.array, this._dummyMask()).forEach(([t, isDummy], i) => {
      f(t, isDummy, i);
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
   * Dynamic array hash that only depends on the actual values (not the padding).
   */
  hash() {
    let type = ProvableType.get(this.innerType);

    // assert that all padding elements are 0. this allows us to pack values into blocks
    let NULL = ProvableType.synthesize(type);
    this.forEach((x, isPadding) => {
      Provable.assertEqualIf(isPadding, this.innerType, x, NULL);
    });

    // create blocks of 2 field elements each
    // TODO abstract this into a `chunk()` method that returns a DynamicArray<StaticArray<T>>
    let mustPack = packedFieldSize(type) > 1;
    let elementSize = bitSize(type);
    let elementsPerHalfBlock = Math.floor(254 / elementSize);
    if (elementsPerHalfBlock === 0) elementsPerHalfBlock = 1; // larger types are compressed

    let elementsPerBlock = 2 * elementsPerHalfBlock;
    assert(!mustPack, 'TODO'); // this should get a separate branch here

    // we pack the length at the beginning of the first block
    // for efficiency (to avoid unpacking the length), we first put zeros at the beginning
    // and later just add the length to the first block
    let elementsPerUint32 = Math.max(Math.floor(32 / elementSize), 1);
    let array = fill(elementsPerUint32, NULL).concat(this.array);

    let Block = StaticArray(type, elementsPerBlock);
    let maxBlocks = Math.ceil(
      (elementsPerUint32 + this.maxLength) / elementsPerBlock
    );
    let Blocks = DynamicArray(Block, { maxLength: maxBlocks });

    // nBlocks = ceil(length / elementsPerBlock) = floor((length + elementsPerBlock - 1) / elementsPerBlock)
    let nBlocks = UInt32.Unsafe.fromField(
      this.length.add(elementsPerUint32 + elementsPerBlock - 1)
    ).div(elementsPerBlock).value;
    let padded = pad(array, maxBlocks * elementsPerBlock, NULL);
    let chunked = chunk(padded, elementsPerBlock).map(Block.from);
    let blocks = new Blocks(chunked, nBlocks).map(
      StaticArray(Field, 2),
      (block) => {
        let firstHalf = block.array
          .slice(0, elementsPerHalfBlock)
          .map((el) => packToField(type, el));
        let secondHalf = block.array
          .slice(elementsPerHalfBlock)
          .map((el) => packToField(type, el));
        return [pack(firstHalf, elementSize), pack(secondHalf, elementSize)];
      }
    );

    // add length to the first block
    let firstBlock = blocks.array[0]!;
    firstBlock.set(0, firstBlock.get(0).add(this.length).seal());

    // TODO remove
    // Provable.log({
    //   elementsPerUint32,
    //   elementSize,
    //   elementsPerBlock,
    //   maxBlocks,
    //   hash: blocks.array.flatMap((x) => x.array),
    // });

    // now hash the 2-field elements blocks, on permutation at a time
    // TODO: first we hash the length, but this should be included in the rest
    let state = Poseidon.initialState();
    blocks.forEach((block, isPadding) => {
      let newState = Poseidon.update(state, block.array);
      state[0] = Provable.if(isPadding, state[0], newState[0]);
      state[1] = Provable.if(isPadding, state[1], newState[1]);
      state[2] = Provable.if(isPadding, state[2], newState[2]);
    });
    return state[0];
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

  /**
   * Returns true if the index is a dummy index,
   * i.e. not actually in the array.
   */
  isDummyIndex(i: number) {
    return this._dummyMask()[i];
  }

  toValue() {
    assertHasProperty(this.constructor, 'provable', 'Need subclass');
    return (this.constructor.provable as Provable<this, V[]>).toValue(this);
  }
}

/**
 * Base class of all DynamicArray subclasses
 */
DynamicArray.Base = DynamicArrayBase;

function provable<T, V, Class extends typeof DynamicArrayBase<T, V>>(
  type: ProvableHashablePure<T, V>,
  Class: Class
): TypeBuilderPure<InstanceType<Class>, V[]>;

function provable<T, V, Class extends typeof DynamicArrayBase<T, V>>(
  type: ProvableHashable<T, V>,
  Class: Class
): TypeBuilder<InstanceType<Class>, V[]>;

function provable<T, V, Class extends typeof DynamicArrayBase<T, V>>(
  type: ProvableHashable<T, V>,
  Class: Class
) {
  let maxLength = Class.maxLength;
  let NULL = type.toValue(ProvableType.synthesize(type));

  return (
    TypeBuilder.shape({
      array: Provable.Array(type, maxLength),
      length: Field,
    })
      .forConstructor((t) => new Class(t.array, t.length))

      // check has to validate length in addition to the other checks
      .withAdditionalCheck(({ length }) => {
        assertInRange16(length, maxLength);
      })

      // convert to/from plain array that has the _actual_ length
      .mapValue<V[]>({
        there({ array, length }) {
          return array.slice(0, Number(length));
        },
        back(array) {
          let padded = pad(array, maxLength, NULL);
          return { array: padded, length: BigInt(array.length) };
        },
        distinguish: (s) => s instanceof DynamicArrayBase,
      })

      // custom hash input
      .hashInput(({ array, length }) => {
        let lengthInput: HashInput = { packed: [[length, 32]] };
        let arrayInput = array.map((x): HashInput => {
          let { fields = [], packed = [] } = type.toInput(x);
          return {
            packed: fields
              .map((x) => [x, 254] as [Field, number])
              .concat(packed),
          };
        });
        return [lengthInput, ...arrayInput].reduce(
          HashInput.append,
          HashInput.empty
        );
      })
  );
}

// serialize/deserialize

ProvableFactory.register(DynamicArray, {
  typeToJSON(constructor) {
    return {
      maxLength: constructor.maxLength,
      innerType: serializeProvableType(constructor.prototype.innerType),
    };
  },

  typeFromJSON(json) {
    let innerType = deserializeProvableType(json.innerType);
    return DynamicArray(innerType as ProvableHashableType, {
      maxLength: json.maxLength,
    });
  },

  valueToJSON(_, { array, length }) {
    return array.slice(0, Number(length)).map((v) => serializeProvable(v));
  },

  valueFromJSON(type, value) {
    let array = value.map((v) => deserializeProvable(v));
    return type.from(array);
  },
});
