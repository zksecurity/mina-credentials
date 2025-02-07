import { DynamicSHA2, DynamicString, StaticArray } from '../dynamic.ts';
import { Bigint2048, rsaVerify65537 } from '../rsa/rsa.ts';
import { fetchPublicKeyFromDNS, prepareEmailForVerification } from './dkim.ts';
import { assert } from '../util.ts';
import { parseRSASubjectPublicKeyInfo } from './der-parse.ts';
import { fromBase64 } from './base64.ts';
import { bytesToBigintBE } from '../rsa/utils.ts';
import {
  Experimental,
  MerkleList,
  Option,
  Proof,
  Provable,
  Struct,
  UInt32,
  UInt8,
  ZkProgram,
} from 'o1js';
import { Block32, Bytes32, State32 } from '../dynamic/dynamic-sha2.ts';

export {
  ProvableEmail,
  verifyEmailSimple,
  prepareProvableEmail,
  verifyEmail,
  verifyEmailHeader,
  hashProgram,
  headerAndBodyProgram,
};

type ProvableEmail = {
  /**
   * The email header in canonicalized form, i.e. the form that was signed.
   */
  header: string | DynamicString;

  /**
   * The email body in canonicalized form, i.e. the form that was signed.
   */
  body: string | DynamicString;

  /**
   * RSA public key that signed the email.
   */
  publicKey: Bigint2048;

  /**
   * The RSA signature of the email.
   */
  signature: Bigint2048;
};

/**
 * Simple provable method to verify an email. Only for demonstration purposes.
 *
 * **Note**: This uses more than 150k constraints, so it doesn't work inside a Pickles proof which has size limited to 2^16 constraints.
 * `verifyEmail()` achieves the same functionality by breaking up the logic into several proofs.
 */
function verifyEmailSimple(email: ProvableEmail) {
  // provable types with max lengths
  let body = DynamicString.from(email.body);
  let header = DynamicString.from(email.header);

  // compute and compare the body hash
  let bodyHash = body.hashToBytes('sha2-256');
  let bodyHashBase64 = bodyHash.base64Encode();

  // TODO: show that body hash is contained at the correct position from header,
  // using a secure string matching circuit
  // (might be helpful to use the dkim header as hint since it is fairly strictly formatted,
  // and known to come last in the header, and then reassemble with the other headers)

  // TODO: this is just a sanity check and not secure at all
  header.assertContains(
    StaticArray.from(UInt8, bodyHashBase64.bytes),
    'verifyEmail: body hash mismatch'
  );

  // hash the header
  let headerHash = header.hashToBytes('sha2-256');

  // verify the signature
  rsaVerify65537(headerHash, email.signature, email.publicKey);
}

async function prepareProvableEmail(email: string): Promise<ProvableEmail> {
  let { canonicalBody, canonicalHeader, dkimHeader } =
    prepareEmailForVerification(email);
  assert(dkimHeader.hashAlgo === 'sha256', 'must use sha256 hash');
  assert(dkimHeader.signAlgo === 'rsa', 'must use rsa signature');

  let { publicKeyBytesDer, modulusLength } = await fetchPublicKeyFromDNS(
    dkimHeader
  );
  assert(modulusLength === 2048, 'modulus length must be 2048');

  // parse DER-encoded `SubjectPublicKeyInfo`
  let { n, e } = parseRSASubjectPublicKeyInfo(publicKeyBytesDer);

  assert(e === 65537n, 'public exponent must be 65537');
  let publicKey = Bigint2048.from(n);

  // signature encoding:
  // https://datatracker.ietf.org/doc/html/rfc3447#section-4.1
  let s = bytesToBigintBE(fromBase64(dkimHeader.signature));
  let signature = Bigint2048.from(s);

  return { header: canonicalHeader, body: canonicalBody, publicKey, signature };
}

function ProvableEmail({
  maxHeaderLength,
  maxBodyLength,
}: {
  maxHeaderLength: number;
  maxBodyLength: number;
}) {
  const Header = DynamicString({ maxLength: maxHeaderLength });
  const Body = DynamicString({ maxLength: maxBodyLength });

  return class extends Struct({
    header: Header,
    body: Body,
    publicKey: Bigint2048,
    signature: Bigint2048,
  }) {
    static Header = Header;
    static Body = Body;
  };
}

// below are the real zkemail circuits, split into one entrypoint circuit and 2 zkprograms

/**
 * Merkelized list of SHA256 blocks, for passing them down a recursive program.
 */
class MerkleBlocks extends MerkleList.create(
  Block32,
  DynamicSHA2.commitBlock256
) {
  /**
   * Pop off `n` elements from the end of the Merkle list. The return values are:
   * - `remaining`: The new Merkle list with elements popped off (input list is not mutated)
   * - `tail`: The removed elements, in their original order.
   *   Since there might be less than `n` elements in the list, `tail` is an array of options.
   *
   * The method guarantees that pushing all the `Some` options back to `remaining` would result in the original list.
   */
  static popTail(
    blocks: MerkleBlocks,
    n: number
  ): { remaining: MerkleBlocks; tail: Option<Block32>[] } {
    blocks = blocks.clone();
    let tail: Option<Block32>[] = Array(n);

    for (let i = n - 1; i >= 0; i--) {
      tail[i] = blocks.popOption();
    }
    return { remaining: blocks, tail };
  }
}

// 9 is on the high end, leads to 47k constraints
const BLOCKS_PER_RECURSIVE_PROOF = 9;
const BLOCKS_PER_BASE_PROOF = 11;

/**
 * A generic ZkProgram that hashes an arbitrary number of SHA256 blocks.
 */
let hashProgram = ZkProgram({
  name: 'recursive-hash',

  publicInput: MerkleBlocks,
  publicOutput: State32,

  methods: {
    // base method that starts hashing from the initial state and guarantees to process all input blocks
    hashBase: {
      privateInputs: [],
      async method(blocks: MerkleBlocks) {
        let state = DynamicSHA2.initialState256(256);

        blocks.forEach(BLOCKS_PER_BASE_PROOF, (block, isDummy) => {
          let nextState = DynamicSHA2.hashBlock256(state, block);
          state = Provable.if(isDummy, State32, state, nextState);
        });
        return { publicOutput: state };
      },
    },

    // method that hashes recursively, handles arbitrarily many blocks
    hashRecursive: {
      privateInputs: [],
      async method(blocks: MerkleBlocks) {
        let state = await hashBlocks(blocks, {
          blocksInThisProof: BLOCKS_PER_RECURSIVE_PROOF,
          proofsEnabled: hashProgram.proofsEnabled,
        });
        return { publicOutput: state };
      },
    },
  },
});

/**
 * Wrapper around `hashProgram`, which hashes an arbitrary number of blocks with SHA256.
 *
 * The number of blocks to hash in the current proof is configurable.
 */
async function hashBlocks(
  blocks: MerkleBlocks,
  options: { blocksInThisProof: number; proofsEnabled?: boolean }
): Promise<State32> {
  let { blocksInThisProof, proofsEnabled = true } = options;

  // split blocks into remaining part and final part
  // the final part is done in this proof, the remaining part is done recursively
  let { remaining, tail } = MerkleBlocks.popTail(blocks, blocksInThisProof);

  // recursively hash the first, "remaining" part
  let proof = await Provable.witnessAsync(hashProgram.Proof, async () => {
    // optionally disable the inner proof
    let originalProofsEnabled = hashProgram.proofsEnabled;
    if (!proofsEnabled) hashProgram.setProofsEnabled(false);

    // convert the blocks to constants
    let blocksForProof = Provable.toConstant(MerkleBlocks, remaining.clone());

    // figure out if we can call the base method or need to recurse
    let nBlocksRemaining = remaining.lengthUnconstrained().get();
    let proof: Proof<MerkleBlocks, State32>;

    if (nBlocksRemaining <= BLOCKS_PER_BASE_PROOF) {
      console.log({ nBlocksRemaining, method: 'hashBase' });
      ({ proof } = await hashProgram.hashBase(blocksForProof));
    } else {
      console.log({ nBlocksRemaining, method: 'hashRecursive' });
      ({ proof } = await hashProgram.hashRecursive(blocksForProof));
    }
    hashProgram.setProofsEnabled(originalProofsEnabled);
    return proof;
  });
  proof.declare();
  proof.verify();

  // constrain public input to match the remaining blocks
  remaining.hash.assertEquals(proof.publicInput.hash);

  // continue hashing the final part
  let state = proof.publicOutput;
  tail.forEach(({ isSome, value: block }) => {
    let nextState = DynamicSHA2.hashBlock256(state, block);
    state = Provable.if(isSome, State32, nextState, state);
  });
  return state;
}

class HeaderAndBodyBlocks extends Struct({
  headerBlocks: MerkleBlocks,
  bodyBlocks: MerkleBlocks,
}) {}
class HeaderAndBodyState extends Struct({
  headerState: State32,
  bodyState: State32,
}) {}

// assumes that 10 blocks = 640 bytes are enough for the header
const HEADER_BLOCKS_TOTAL = 10;
const HEADER_BLOCKS_IN_INNER_PROOF = 9;
const HEADER_BLOCKS_IN_OUTER_PROOF =
  HEADER_BLOCKS_TOTAL - HEADER_BLOCKS_IN_INNER_PROOF;

const BODY_BLOCKS_IN_INNER_PROOF =
  BLOCKS_PER_RECURSIVE_PROOF - HEADER_BLOCKS_IN_INNER_PROOF;
// 9 - 9 = 0, which means we support 0 + 11 = 11 body blocks in 3 proofs
// more are supported by 4 proofs

let headerAndBodyProgram = ZkProgram({
  name: 'header-and-body-hash',

  publicInput: HeaderAndBodyBlocks,
  publicOutput: HeaderAndBodyState,

  methods: {
    run: {
      privateInputs: [],
      async method({ headerBlocks, bodyBlocks }: HeaderAndBodyBlocks) {
        // hash the header here, and the body recursively
        let headerState = DynamicSHA2.initialState256(256);

        headerBlocks.forEach(HEADER_BLOCKS_IN_INNER_PROOF, (block, isDummy) => {
          let nextState = DynamicSHA2.hashBlock256(headerState, block);
          headerState = Provable.if(isDummy, State32, headerState, nextState);
        });

        let bodyState = await hashBlocks(bodyBlocks, {
          blocksInThisProof: BODY_BLOCKS_IN_INNER_PROOF,
          proofsEnabled: headerAndBodyProgram.proofsEnabled,
        });
        return { publicOutput: { headerState, bodyState } };
      },
    },
  },
});
let headerAndBodyRecursive = Experimental.Recursive(headerAndBodyProgram);

async function verifyEmail(
  email: ProvableEmail,
  { proofsEnabled = true } = {}
) {
  // 3k constraints to witness the email

  // provable types with max lengths
  let body = DynamicString.from(email.body);
  let header = DynamicString.from(email.header);

  // pad header/body into blocks, convert those into a Merkle list
  // 3.7k constraints for header length 500
  let headerBlocksDynamic = DynamicSHA2.padding256(header);
  let bodyBlocksDynamic = DynamicSHA2.padding256(body);

  // 200 constraints for header length 500
  let headerBlocks = headerBlocksDynamic.merkelize(DynamicSHA2.commitBlock256);
  let bodyBlocks = bodyBlocksDynamic.merkelize(DynamicSHA2.commitBlock256);

  // pop off header tail
  let { remaining: headerBlocksInner, tail: headerTail } = MerkleBlocks.popTail(
    headerBlocks,
    HEADER_BLOCKS_IN_OUTER_PROOF
  );

  // hash header and body in inner proof
  // (we allow disabling proofs to run this quickly)
  let originalProofsEnabled1 = hashProgram.proofsEnabled;
  let originalProofsEnabled2 = headerAndBodyProgram.proofsEnabled;
  hashProgram.setProofsEnabled(proofsEnabled);
  headerAndBodyProgram.setProofsEnabled(proofsEnabled);

  let { headerState, bodyState } = await headerAndBodyRecursive.run({
    headerBlocks: headerBlocksInner,
    bodyBlocks,
  });
  hashProgram.setProofsEnabled(originalProofsEnabled1);
  headerAndBodyProgram.setProofsEnabled(originalProofsEnabled2);

  // continue hashing the header tail
  // 5.3k * HEADER_BLOCKS_IN_OUTER_PROOF constraints
  headerTail.forEach(({ isSome, value: block }) => {
    let nextState = DynamicSHA2.hashBlock256(headerState, block);
    headerState = Provable.if(isSome, State32, nextState, headerState);
  });

  // convert final states to bytes
  let headerHash = Bytes32.from(
    headerState.array.flatMap((x) => x.toBytesBE())
  );
  let bodyHash = Bytes32.from(bodyState.array.flatMap((x) => x.toBytesBE()));

  // 1.6k constraints
  let bodyHashBase64 = bodyHash.base64Encode();

  // TODO: show that body hash is contained at the correct position from header,
  // using a secure string matching circuit
  // (might be helpful to use the dkim header as hint since it is fairly strictly formatted,
  // and known to come last in the header, and then reassemble with the other headers)

  // TODO: this is just a sanity check and not secure at all
  // 22k constraints  :(
  Provable.asProver(() => {
    header.assertContains(
      StaticArray.from(UInt8, bodyHashBase64.bytes),
      'verifyEmail: body hash mismatch'
    );
  });

  // verify the signature
  // 12k constraints
  rsaVerify65537(headerHash, email.signature, email.publicKey);
}

// HEADER ONLY:

type ProvableEmailHeader = {
  /**
   * The email header in canonicalized form, i.e. the form that was signed.
   */
  header: string | DynamicString;

  /**
   * RSA public key that signed the email.
   */
  publicKey: Bigint2048;

  /**
   * The RSA signature of the email.
   */
  signature: Bigint2048;
};

/**
 * This is a variant of `verifyEmail()` which only verifies the header, not the body.
 */
async function verifyEmailHeader(
  email: ProvableEmailHeader,
  { proofsEnabled = true } = {}
) {
  // provable types with max lengths
  let header = DynamicString.from(email.header);

  // pad header into blocks, convert those into a Merkle list, and hash using `hashBlocks()`
  // 3.7k constraints for header length 500
  let headerBlocksDynamic = DynamicSHA2.padding256(header);

  // 200 constraints for header length 500
  let headerBlocks = headerBlocksDynamic.merkelize(DynamicSHA2.commitBlock256);

  // 5.3k constraints per block
  let state = await hashBlocks(headerBlocks, {
    blocksInThisProof: 1,
    proofsEnabled,
  });
  // convert final state to bytes
  let headerHash = Bytes32.from(state.array.flatMap((x) => x.toBytesBE()));

  // verify the signature
  // 12k constraints
  rsaVerify65537(headerHash, email.signature, email.publicKey);
}
