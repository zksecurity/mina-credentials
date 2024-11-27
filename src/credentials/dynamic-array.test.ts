import { Provable, UInt8 } from 'o1js';
import { DynamicArray, DynamicString } from '../dynamic.ts';
import { log } from './dynamic-hash.ts';
import assert from 'assert';

// concatenation of two strings

let String1 = DynamicString({ maxLength: 100 });
let String2 = DynamicString({ maxLength: 100 });

let StringLike1 = DynamicArray(UInt8, { maxLength: String1.maxLength });
let StringLike2 = DynamicArray(UInt8, { maxLength: String2.maxLength });
let String12 = DynamicString({
  maxLength: String1.maxLength + String2.maxLength,
});

console.log(
  'baseline',
  await runAndConstraints(() => {
    let s1 = Provable.witness(String1, () => 'blub');
    let s2 = Provable.witness(String2, () => 'blob');
  })
);

console.log(
  'baseline + chunk',
  await runAndConstraints(() => {
    let s1 = Provable.witness(String1, () => 'blub');
    let s2 = Provable.witness(String2, () => 'blob');
    s1.chunk(8);
  })
);

console.log(
  'concat naive',
  await runAndConstraints(() => {
    let s1 = Provable.witness(StringLike1, () => String1.from('blub').array);
    let s2 = Provable.witness(StringLike2, () => String2.from('blob').array);

    let s12 = s1.concat(s2);
    log(new String12(s12.array, s12.length));
  })
);

console.log(
  'concat transposed',
  await runAndConstraints(() => {
    let s1 = Provable.witness(String1, () => 'blub');
    let s2 = Provable.witness(String2, () => 'blob');

    let s12 = s1.concatTransposed(s2);
    log(new String12(s12.array, s12.length));
  })
);

console.log(
  'concat with hashing',
  await runAndConstraints(() => {
    let s1 = Provable.witness(String1, () => 'blub');
    let s2 = Provable.witness(String2, () => 'blob');

    let s12 = s1.concatByHashing(s2);
    log(new String12(s12.array, s12.length));
  })
);

console.log(
  'concat string',
  await runAndConstraints(() => {
    let s1 = Provable.witness(String1, () => 'blub');
    let s2 = Provable.witness(String2, () => 'blob');

    let s12 = s1.concat(s2);
    log(s12);
  })
);

// substring check

{
  const String = DynamicString({ maxLength: 100 });
  const SmallString = DynamicString({ maxLength: 10 });

  function main() {
    let string = Provable.witness(String, () => 'hello world');
    let contained = Provable.witness(SmallString, () => 'lo wo');

    let i = string.assertContains(contained);
    i.assertEquals(3);

    if (Provable.inProver()) {
      let notContained = Provable.witness(SmallString, () => 'worldo');
      assert.throws(() => string.assertContains(notContained));
    }
  }

  // can run normally
  main();

  // can run while checking constraints
  console.log(
    `substring check (${SmallString.maxLength} in ${String.maxLength})`,
    await runAndConstraints(main)
  );
}

// helper

async function runAndConstraints(fn: () => Promise<void> | void) {
  await Provable.runAndCheck(fn);
  return (await Provable.constraintSystem(fn)).summary();
}
