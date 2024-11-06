import { DynamicArray } from './dynamic-array.ts';
import { DynamicString } from './dynamic-string.ts';
import './dynamic-record.ts';
import { hashDynamic, hashString, packDynamic } from './dynamic-hash.ts';
import { test } from 'node:test';
import * as nodeAssert from 'node:assert';
import { Bytes, Field, MerkleList, Poseidon, Provable, UInt8 } from 'o1js';
import { DynamicRecord } from './dynamic-record.ts';

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
  });

  // arrays of strings
  let shortArray = [shortString, shortString];
  let ShortArray = DynamicArray(ShortString, { maxLength: 5 });
  let longArray = Array(8).fill(longString);
  let LongArray = DynamicArray(LongString, { maxLength: 10 });

  let shortArrayHash = hashDynamic(shortArray);
  let longArrayHash = hashDynamic(longArray);

  await test('hash arrays of strings', () => {
    Provable.witness(ShortArray, () => shortArray)
      .hash()
      .assertEquals(shortArrayHash, 'short array');

    Provable.witness(LongArray, () => longArray)
      .hash()
      .assertEquals(longArrayHash, 'long array');
  });

  // single-field values
  await test('plain values', () => {
    // stay the same when packing
    packDynamic(-1n).assertEquals(Field(-1n), 'pack bigint');
    packDynamic(true).assertEquals(Field(1), 'pack boolean');
    packDynamic(123).assertEquals(Field(123), 'pack number');

    // hash is plain poseidon hash
    hashDynamic(-1n).assertEquals(Poseidon.hash([Field(-1n)]), 'hash bigint');
    hashDynamic(true).assertEquals(Poseidon.hash([Field(1)]), 'hash boolean');
    hashDynamic(123).assertEquals(Poseidon.hash([Field(123)]), 'hash number');
  });

  // records of plain values
  let record = { a: shortString, b: 1, c: true, d: -1n };
  let recordHash = hashDynamic(record);

  let Record = DynamicRecord({}, { maxEntries: 5 });

  await test('hash records', () => {
    Provable.witness(Record, () => record)
      .hash()
      .assertEquals(recordHash, 'record');
  });

  // arrays of records
  let array = [record, record, record];
  let arrayHash = hashDynamic(array);

  let RecordArray = DynamicArray(Record, { maxLength: 5 });

  // await test('hash arrays of records', () => {
  Provable.witness(RecordArray, () => array)
    .hash()
    .assertEquals(arrayHash, 'array');
  // });
}

await test('outside circuit', () => main());
await test('inside circuit', () => Provable.runAndCheck(main));

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
