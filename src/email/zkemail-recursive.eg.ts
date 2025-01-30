import { readFile } from 'fs/promises';
import { Provable, ZkProgram } from 'o1js';
import {
  hashProgram,
  headerAndBodyProgram,
  prepareProvableEmail,
  ProvableEmail,
  verifyEmail,
} from './zkemail.ts';
import { mapObject } from '../util.ts';

const compileAndRunProgram = true;

let email = await readFile(
  `${import.meta.dirname}/test-emails/email-good.eml`,
  'utf-8'
);
let provableEmail = await prepareProvableEmail(email);

class Email extends ProvableEmail({
  maxHeaderLength: 500,
  maxBodyLength: 700,
}) {}

async function main() {
  let email = Provable.witness(Email, () => provableEmail);
  await verifyEmail(email, { proofsEnabled });
}

// just run
let proofsEnabled = false;
console.time('zkemail plain');
await main();
console.timeEnd('zkemail plain');

// run with constraints
console.time('zkemail witness generation');
await Provable.runAndCheck(() => main());
console.timeEnd('zkemail witness generation');

// log constraints
console.time('hash constraints');
console.log(mapObject(await hashProgram.analyzeMethods(), (m) => m.summary()));
console.timeEnd('hash constraints');

console.time('header and body constraints');
console.log((await headerAndBodyProgram.analyzeMethods()).run.summary());
console.timeEnd('header and body constraints');

console.time('zkemail constraints');
console.log((await Provable.constraintSystem(main)).summary());
console.timeEnd('zkemail constraints');

if (compileAndRunProgram) {
  let verifyProgram = ZkProgram({
    name: 'zkemail',
    methods: {
      run: {
        privateInputs: [],
        async method() {
          await main();
        },
      },
    },
  });

  // compile, prove
  proofsEnabled = true;
  console.time('compile hash');
  await hashProgram.compile();
  console.timeEnd('compile hash');

  console.time('compile header and body');
  await headerAndBodyProgram.compile();
  console.timeEnd('compile header and body');

  console.time('compile verify');
  await verifyProgram.compile();
  console.timeEnd('compile verify');

  console.time('prove');
  await verifyProgram.run();
  console.timeEnd('prove');
}
