import { Provable } from 'o1js';
import { DynamicString } from '../dynamic.ts';
import { log } from './dynamic-hash.ts';

let String1 = DynamicString({ maxLength: 100 });
let String2 = DynamicString({ maxLength: 100 });

let String12 = DynamicString({
  maxLength: String1.maxLength + String2.maxLength,
});

console.log(
  'concat naive',
  await runAndConstraints(() => {
    let s1 = Provable.witness(String1, () => 'blub');
    let s2 = Provable.witness(String2, () => 'blob');

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

async function runAndConstraints(fn: () => Promise<void> | void) {
  await Provable.runAndCheck(fn);
  return (await Provable.constraintSystem(fn)).summary();
}
