import { readFile } from 'fs/promises';
import { Provable } from 'o1js';
import {
  prepareProvableEmail,
  ProvableEmail,
  verifyEmailSimple,
} from './zkemail.ts';

let email = await readFile(
  `${import.meta.dirname}/test-emails/email-good.eml`,
  'utf-8'
);
let provableEmail = await prepareProvableEmail(email);

class Email extends ProvableEmail({
  maxHeaderLength: 500,
  maxBodyLength: 700,
}) {}

function main() {
  let email = Provable.witness(Email, () => provableEmail);
  verifyEmailSimple(email);
}

// just run
console.time('zkemail plain');
main();
console.timeEnd('zkemail plain');

// run with constraints
console.time('zkemail witness generation');
await Provable.runAndCheck(main);
console.timeEnd('zkemail witness generation');

// log constraints
console.time('zkemail constraints');
console.log((await Provable.constraintSystem(main)).summary());
console.timeEnd('zkemail constraints');
