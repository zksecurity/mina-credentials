import { readFile } from 'fs/promises';
import { initializeBindings, Provable, ZkProgram } from 'o1js';
import {
  hashProgram,
  prepareProvableEmail,
  ProvableEmail,
  verifyEmailRecursive,
} from './zkemail.ts';
import { mapObject } from '../util.ts';

const compileAndRunProgram = false;

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
  await verifyEmailRecursive(email, { proofsEnabled });
}

// just run
let proofsEnabled = false;
console.time('zkemail plain');
await main();
console.timeEnd('zkemail plain');

await initializeBindings();

// run with constraints
console.time('zkemail witness generation');
await Provable.runAndCheck(() => main());
console.timeEnd('zkemail witness generation');

// log constraints
console.time('hash constraints');
console.log(mapObject(await hashProgram.analyzeMethods(), (m) => m.summary()));
console.timeEnd('hash constraints');

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
  console.time('compile verify');
  await verifyProgram.compile();
  console.timeEnd('compile verify');

  console.time('prove');
  await verifyProgram.run();
  console.timeEnd('prove');
}
