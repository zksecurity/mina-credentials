import { Field, Provable, UInt32 } from 'o1js';
import { assertLessThan16, lessThan16 } from './gadgets.ts';

let r = await Provable.constraintSystem(() => {
  let x = Provable.witness(Field, () => 1n);
  let y = Provable.witness(Field, () => 2n);
  // let b = lessThan16(x, y);
  assertLessThan16(UInt32.Unsafe.fromField(x), y);
});

r.print();
