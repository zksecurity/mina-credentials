import { DynamicArray } from './dynamic-array.ts';
import { DynamicString } from './dynamic-string.ts';
import { hashString } from './dynamic-hash.ts';
import { test } from 'node:test';
import * as nodeAssert from 'node:assert';

let shortString = 'hi';
let ShortString = DynamicString({ maxLength: 5 });

let longString =
  'Poseidon (/pəˈsaɪdən, pɒ-, poʊ-/;[1] Greek: Ποσειδῶν) is one of the Twelve Olympians in ancient Greek religion and mythology,' +
  ' presiding over the sea, storms, earthquakes and horses.[2]';
let LongString = DynamicString({ maxLength: 300 });

test('hash strings', () => {
  let shortHash = hashString(shortString);
  ShortString.from(shortString)
    .hash()
    .assertEquals(shortHash, 'hash mismatch (short)');

  let longHash = hashString(longString);
  LongString.from(longString)
    .hash()
    .assertEquals(longHash, 'hash mismatch (long)');

  // we can even convert the `ShortString` into a `LongString`
  LongString.provable
    .fromValue(ShortString.from(shortString))
    .hash()
    .assertEquals(shortHash, 'hash mismatch (short -> long)');

  // (the other way round doesn't work because the string is too long)
  nodeAssert.throws(() => {
    ShortString.provable.fromValue(LongString.from(longString));
  }, /larger than target size/);
});
