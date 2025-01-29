/**
 * This example computes the SHA2 hash of a long string in multiple chunks, using recursion
 * and the `DynamicSHA2` `split()` / `update()` / `finalize()` API.
 */
import { Bytes, SelfProof, ZkProgram } from 'o1js';
import {
  DynamicSHA2,
  DynamicString,
  Sha2IterationState,
  Sha2Iteration,
  Sha2FinalIteration,
} from '../dynamic.ts';
import { mapObject } from '../util.ts';

const String = DynamicString({ maxLength: 850 });
const Bytes32 = Bytes(32);

/**
 * How many SHA2 blocks to process in each proof.
 */
const BLOCKS_PER_ITERATION = 7;

class State extends Sha2IterationState(256) {}
class Iteration extends Sha2Iteration(256, BLOCKS_PER_ITERATION) {}
class FinalIteration extends Sha2FinalIteration(256, BLOCKS_PER_ITERATION) {}

let sha2Update = ZkProgram({
  name: 'sha2-update',
  publicOutput: State,

  methods: {
    initial: {
      privateInputs: [Iteration],
      async method(iteration: Iteration) {
        let state = State.initial();
        let publicOutput = DynamicSHA2.update(state, iteration);
        return { publicOutput };
      },
    },

    recursive: {
      privateInputs: [SelfProof, Iteration],
      async method(proof: SelfProof<undefined, State>, iteration: Iteration) {
        proof.verify();
        let state = proof.publicOutput;
        let publicOutput = DynamicSHA2.update(state, iteration);
        return { publicOutput };
      },
    },
  },
});

class UpdateProof extends ZkProgram.Proof(sha2Update) {}

let sha2Finalize = ZkProgram({
  name: 'sha2-finalize',
  publicOutput: Bytes32,

  methods: {
    run: {
      privateInputs: [String, UpdateProof, FinalIteration],
      async method(
        string: DynamicString,
        proof: UpdateProof,
        iteration: FinalIteration
      ) {
        proof.verify();
        let state = proof.publicOutput;
        let publicOutput = DynamicSHA2.finalize(state, iteration, string);
        return { publicOutput };
      },
    },
  },
});

console.log(mapObject(await sha2Update.analyzeMethods(), (m) => m.summary()));
console.log(mapObject(await sha2Finalize.analyzeMethods(), (m) => m.summary()));

// split up string into chunks to be hashed

let longString = 'hello world!'.repeat(Math.floor(850 / 12));
console.log('string length', longString.length);

let { iterations, final } = DynamicSHA2.split(
  256,
  BLOCKS_PER_ITERATION,
  String.from(longString)
);

console.log('number of iterations (including final):', iterations.length + 1);

console.time('compile');
await sha2Update.compile();
await sha2Finalize.compile();
console.timeEnd('compile');

let [first, ...rest] = iterations;

console.time('proof (initial)');
let { proof } = await sha2Update.initial(first!);
console.timeEnd('proof (initial)');

console.time(`proof (recursive ${rest.length}x)`);
for (let iteration of rest) {
  ({ proof } = await sha2Update.recursive(proof, iteration));
}
console.timeEnd(`proof (recursive ${rest.length}x)`);

console.time('proof (finalize)');
let { proof: finalProof } = await sha2Finalize.run(
  String.from(longString),
  proof,
  final
);
console.timeEnd('proof (finalize)');

console.log('public output:\n', finalProof.publicOutput.toHex());

// compare with expected hash
console.log(
  'expected hash:\n',
  DynamicSHA2.hash(256, String.from(longString)).toHex()
);
