import { Provable } from 'o1js';
import { DynamicString } from '../dynamic.ts';

let String1 = DynamicString({ maxLength: 500 });
let String2 = DynamicString({ maxLength: 100 });

let cs = await Provable.constraintSystem(() => {
  let s1 = Provable.witness(String1, () => 'blub');
  let s2 = Provable.witness(String2, () => 'blob');

  let s12 = s1.concatByHashing(s2);
});

console.log(cs.summary());
