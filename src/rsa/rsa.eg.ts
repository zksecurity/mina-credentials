import { Bytes, ZkProgram } from 'o1js';
import { SHA2 } from '../dynamic/sha2.ts';
import { rsaVerify65537, rsaSign, Bigint2048 } from './rsa.ts';
import { generateRsaKeys65537 } from './utils.ts';

let keys = generateRsaKeys65537();

let message = SHA2.hash(256, 'a test message');
let signature = rsaSign(message, keys);

const Message = Bytes(32);

let rsaProgram = ZkProgram({
  name: 'rsa',
  publicInput: Message,

  methods: {
    run: {
      privateInputs: [Bigint2048, Bigint2048],

      async method(message: Bytes, signature: Bigint2048, modulus: Bigint2048) {
        rsaVerify65537(message, signature, modulus);
      },
    },
  },
});

console.log((await rsaProgram.analyzeMethods()).run.summary());

await rsaProgram.compile();

// Run the program
await rsaProgram.run(
  message,
  Bigint2048.from(signature),
  Bigint2048.from(keys.n)
);
