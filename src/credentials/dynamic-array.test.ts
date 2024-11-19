import { Provable } from 'o1js';
import { DynamicString } from './dynamic-string.ts';

let String1 = DynamicString({ maxLength: 500 });
let String2 = DynamicString({ maxLength: 100 });

let cs = await Provable.constraintSystem(() => {
  let s1 = Provable.witness(String1, () => 'blub');
  let s2 = Provable.witness(String2, () => 'blob');

  s1.concat(s2);
});

console.log(cs.summary());
