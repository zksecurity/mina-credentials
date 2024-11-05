import { DynamicArray } from './dynamic-array.ts';
import { DynamicString } from './dynamic-string.ts';
import { hashString } from './dynamic-hash.ts';
import { test } from 'node:test';

let shortString = 'hi';
let ShortString = DynamicString({ maxLength: 5 });

let longString =
  'Poseidon (/pəˈsaɪdən, pɒ-, poʊ-/;[1] Greek: Ποσειδῶν) is one of the Twelve Olympians in ancient Greek religion and mythology,' +
  ' presiding over the sea, storms, earthquakes and horses.[2]';
let LongString = DynamicString({ maxLength: 300 });

test('hash strings', () => {
  ShortString.from(shortString)
    .hash()
    .assertEquals(hashString(shortString), 'hash mismatch (short)');

  LongString.from(longString)
    .hash()
    .assertEquals(hashString(longString), 'hash mismatch (long)');
});
