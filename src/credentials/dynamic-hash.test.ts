import { DynamicArray } from './dynamic-array.ts';
import { DynamicString } from './dynamic-string.ts';
import './dynamic-record.ts';
import {
  hashArray,
  hashDynamic,
  hashRecord,
  hashSafe,
  hashSafeWithPrefix,
  hashString,
  packToField,
} from './dynamic-hash.ts';
import { test } from 'node:test';
import * as nodeAssert from 'node:assert';
import {
  Bytes,
  Field,
  MerkleList,
  Poseidon,
  Provable,
  UInt32,
  UInt8,
} from 'o1js';
import { DynamicRecord } from './dynamic-record.ts';

// some hash collisions to be aware of, that are also quite natural

hashDynamic(5n).assertEquals(hashDynamic(5), 'bigint ~ number');
hashDynamic(true).assertEquals(hashDynamic(1), 'bool ~ number');
hashDynamic({ a: 0n }).assertEquals(
  hashDynamic({ a: false }),
  'record ~ record with equivalent fields'
);
hashDynamic(undefined).assertEquals(
  hashDynamic(null),
  'undefined ~ null ~ any empty type'
);
hashDynamic('\x01\x02').assertEquals(
  hashDynamic([1, 2].map(UInt8.from)),
  'strings ~ dynamic arrays of bytes'
);
hashDynamic([UInt32.from(0)]).assertEquals(
  hashDynamic([Field(0)]),
  'dynamic arrays of zeros of same length, regardless of packing density of type (because padding is zeros)'
);

// this used to be an unexpected hash collision that was fixed
hashRecord({ '\x00': 0 }).assertNotEquals(hashRecord({}));

let shortString = 'hi';
let ShortString = DynamicString({ maxLength: 5 });
let shortHash = hashString(shortString);

let longString =
  'Poseidon (/pəˈsaɪdən, pɒ-, poʊ-/;[1] Greek: Ποσειδῶν) is one of the Twelve Olympians';

let LongString = DynamicString({ maxLength: 100 });
let longHash = hashString(longString);

async function main() {
  await test('hash strings', () => {
    let shortStringVar = Provable.witness(ShortString, () => shortString);
    shortStringVar.hash().assertEquals(shortHash, 'short string');

    let longStringVar = Provable.witness(LongString, () => longString);
    longStringVar.hash().assertEquals(longHash, 'long string');

    // we can even convert the `ShortString` into a `LongString`
    LongString.from(shortStringVar)
      .hash()
      .assertEquals(shortHash, 'short -> long string');

    // the other way round doesn't work because the string is too long
    nodeAssert.throws(() => {
      ShortString.from(LongString.from(longString));
    }, /larger than target size/);

    // for strings, hashDynamic === packToField === hashString
    hashDynamic(shortString).assertEquals(shortHash, 'short string');
    packToField(shortString).assertEquals(shortHash, 'short string');
    hashDynamic(shortStringVar).assertEquals(shortHash, 'short string');
    packToField(shortStringVar).assertEquals(shortHash, 'short string');
  });

  // arrays of strings
  let shortArray = [shortString, shortString];
  let ShortArray = DynamicArray(ShortString, { maxLength: 5 });
  let longArray = Array(8).fill(longString);
  let LongArray = DynamicArray(LongString, { maxLength: 10 });

  let shortArrayHash = hashDynamic(shortArray);
  let longArrayHash = hashDynamic(longArray);

  await test('hash arrays of strings', () => {
    let shortArrayVar = Provable.witness(ShortArray, () => shortArray);
    shortArrayVar.hash().assertEquals(shortArrayHash, 'short array');

    Provable.witness(LongArray, () => longArray)
      .hash()
      .assertEquals(longArrayHash, 'long array');

    // for arrays, hashDynamic === packToField === hashArray
    hashArray(shortArray).assertEquals(shortArrayHash, 'short array');
    packToField(shortArray).assertEquals(shortArrayHash, 'short array');
    hashDynamic(shortArrayVar).assertEquals(shortArrayHash, 'short array');
    packToField(shortArrayVar).assertEquals(shortArrayHash, 'short array');
  });

  // single-field values
  await test('plain values', () => {
    // stay the same when packing
    packToField(-1n).assertEquals(Field(-1n), 'pack bigint');
    packToField(true).assertEquals(Field(1), 'pack boolean');
    packToField(123).assertEquals(Field(123), 'pack number');
    packToField(undefined).assertEquals(hashSafe([]), 'pack undefined');

    // hash is plain poseidon hash
    hashDynamic(-1n).assertEquals(hashSafe([Field(-1n)]), 'hash bigint');
    hashDynamic(true).assertEquals(hashSafe([Field(1)]), 'hash boolean');
    hashDynamic(123).assertEquals(hashSafe([Field(123)]), 'hash number');
    hashDynamic(undefined).assertEquals(hashSafe([]), 'pack undefined');

    // hash of several plain values is poseidon hash
    hashDynamic(6n, 7, true).assertEquals(hashSafe([6, 7, 1].map(Field)));
  });

  // records of plain values
  let record = { a: shortString, b: 1, c: true, d: -1n };
  let recordHash = hashDynamic(record);

  let Record = DynamicRecord({}, { maxEntries: 5 });

  await test('hash records', () => {
    let recordVar = Provable.witness(Record, () => record);
    recordVar.hash().assertEquals(recordHash, 'record');

    packToField(recordVar).assertEquals(recordHash, 'record');
    hashRecord(record).assertEquals(recordHash, 'record');
  });

  // arrays of records
  let array = [record, record, record];
  let arrayHash = hashDynamic(array);

  let RecordArray = DynamicArray(Record, { maxLength: 5 });

  await test('hash arrays of records', () => {
    let arrayVar = Provable.witness(RecordArray, () => array);

    arrayVar.hash().assertEquals(arrayHash, 'array');
    hashDynamic(array).assertEquals(arrayHash, 'array');
  });
}

await test('outside circuit', () => main());
await test('inside circuit', () => Provable.runAndCheck(main));

// hashSafe

await test('collisions', async () => {
  await test('Poseidon collisions', () => {
    Poseidon.hash([]).assertEquals(Poseidon.hash([Field(0)]));
    Poseidon.hash([]).assertEquals(Poseidon.hash([Field(0), Field(0)]));
    Poseidon.hash([1, 2, 3].map(Field)).assertEquals(
      Poseidon.hash([1, 2, 3, 0].map(Field))
    );
  });

  await test('No hashSafe collisions', () => {
    hashSafe([]).assertNotEquals(hashSafe([0]));
    hashSafe([]).assertNotEquals(hashSafe([0, 0]));
    hashSafe([1, 2, 3]).assertNotEquals(hashSafe([1, 2, 3, 0]));
  });

  await test('hashSafe with prefix', () => {
    hashSafeWithPrefix('blub', [1, 2, 3]).assertNotEquals(
      hashSafeWithPrefix('blob', [1, 2, 3])
    );
  });
});

// comparison of constraint efficiency of different approaches

let cs = await Provable.constraintSystem(() => {
  Provable.witness(LongString, () => longString).hash();
});
console.log('constraints: string hash (100)', cs.rows);

// merkle list of characters
// list is represented as a single hash, so the equivalent of hashing is unpacking the entire list
let CharList = MerkleList.create(UInt8, (hash, { value }) =>
  Poseidon.hash([hash, value])
);

let cs2 = await Provable.constraintSystem(() => {
  Provable.witness(CharList, () =>
    CharList.from(Bytes.fromString(longString).bytes)
  ).forEach(100, (_item, _isDummy) => {});
});
console.log('constraints: merkle list of chars (100)', cs2.rows);
