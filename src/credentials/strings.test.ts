import { Provable } from 'o1js';
import { DynamicBytes } from './dynamic-bytes.ts';
import assert from 'node:assert';

const Bytes = DynamicBytes({ maxLength: 50 });

let string = Bytes.fromString('hello world');

let contained = Bytes.fromString('lo wo');
let containedIndex = 3;

let notContained = Bytes.fromString('worldo');

function circuit() {
  let stringP = Provable.witness(Bytes, () => string);
  let containedP = Provable.witness(Bytes, () => contained);

  let i = stringP.assertContains(containedP);
  i.assertEquals(containedIndex);

  assert.throws(() => stringP.assertContains(notContained));
}

// can run normally
circuit();

// can run while checking constraints
await Provable.runAndCheck(circuit);
