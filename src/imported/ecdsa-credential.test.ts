import { owner } from '../../tests/test-utils.ts';
import { EcdsaEthereum } from './ecdsa-credential.ts';

const EcdsaCredential = await EcdsaEthereum.Credential({
  maxMessageLength: 50,
});

console.time('ecdsa constraints');
let cs = await EcdsaCredential.program.analyzeMethods();
console.log(cs.run.summary());
console.timeEnd('ecdsa constraints');

console.time('ecdsa compile');
let vk = await EcdsaCredential.compile({ proofsEnabled: false });
console.timeEnd('ecdsa compile');

console.time('ecdsa dummy');
let credDummy = await EcdsaCredential.dummy({
  owner,
  data: { message: 'test test' },
});
console.timeEnd('ecdsa dummy');

// create ecdsa cred from zkpass data
