import { DynamicSHA2, DynamicString, StaticArray } from '../dynamic.ts';
import { Bigint2048, rsaVerify65537 } from '../rsa/rsa.ts';
import { fetchPublicKeyFromDNS, prepareEmailForVerification } from './dkim.ts';
import { assert } from '../util.ts';
import { parseRSASubjectPublicKeyInfo } from './der-parse.ts';
import { fromBase64 } from './base64.ts';
import { bytesToBigintBE } from '../rsa/utils.ts';
import {
  MerkleList,
  Option,
  Proof,
  Provable,
  Struct,
  UInt32,
  UInt8,
  ZkProgram,
} from 'o1js';
import { Block32, Bytes32, State32 } from '../credentials/dynamic-sha2.ts';

export {
  ProvableEmail,
  verifyEmail,
  prepareProvableEmail,
  verifyEmailRecursive,
  hashProgram,
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
 * Simple provable method to verify an email for demonstration purposes.
 *
 * Uses more than 150k constraints so needs breaking up into several proofs to actually use.
 */
function verifyEmail(email: ProvableEmail) {
  // provable types with max lengths
  let body = DynamicString.from(email.body);
  let header = DynamicString.from(email.header);

  // compute and compare the body hash
  // TODO: this needs a recursive proof
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
  // TODO: this needs a recursive proof
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

class MerkleBlocks extends MerkleList.create(
  Block32,
  DynamicSHA2.commitBlock256
) {
  /**
   * Pop off `n` elements from the end of the Merkle list. The return value is a tuple of:
   * - The new Merkle list with elements popped off (the input list is not mutated)
   * - The popped off elements, in their original order. Since there might be less than `n` elements in the list, this is an array of options.
   */
  static popTail(
    blocks: MerkleBlocks,
    n: number
  ): [MerkleBlocks, Option<Block32>[]] {
    blocks = blocks.clone();
    let tail: Option<Block32>[] = Array(n);

    for (let i = n - 1; i >= 0; i--) {
      tail[i] = blocks.popOption();
    }
    return [blocks, tail];
  }
}

// 9 is on the high end, leads to 47k constraints
const BLOCKS_PER_RECURSIVE_PROOF = 9;

let hashProgram = ZkProgram({
  name: 'recursive-hash',

  publicInput: MerkleBlocks,
  publicOutput: State32,

  methods: {
    // main method that hashes recursively
    hashRecursive: {
      privateInputs: [],
      async method(blocks: MerkleBlocks) {
        let state = await hashBlocks(blocks, {
          blocksInThisProof: BLOCKS_PER_RECURSIVE_PROOF,
          blocksPerRecursiveProof: BLOCKS_PER_RECURSIVE_PROOF,
          proofsEnabled: hashProgram.proofsEnabled,
        });
        return { publicOutput: state };
      },
    },

    // base method that starts hashing from the initial state and must process all input blocks
    hashBase: {
      privateInputs: [],
      async method(blocks: MerkleBlocks) {
        let state = DynamicSHA2.initialState256(256);

        blocks.forEach(BLOCKS_PER_RECURSIVE_PROOF, (block, isDummy) => {
          let nextState = DynamicSHA2.hashBlock256(state, block);
          state = Provable.if(isDummy, State32, state, nextState);
        });
        return { publicOutput: state };
      },
    },
  },
});

/**
 * Wrapper around hashProgram, which splits up the input blocks into a main part and a final part,
 * hashes the main part recursively (determining which program method to use based on whether the
 * input is empty or not), and then hashes the final part and returns the final state.
 */
async function hashBlocks(
  blocks: MerkleBlocks,
  options: {
    blocksInThisProof: number;
    blocksPerRecursiveProof: number;
    proofsEnabled?: boolean;
  }
): Promise<State32> {
  let {
    blocksInThisProof,
    blocksPerRecursiveProof,
    proofsEnabled = true,
  } = options;

  // split blocks into remaining part and final part
  // the final part is done in this proof, the remaining part is done recursively
  let [remaining, tail] = MerkleBlocks.popTail(blocks, blocksInThisProof);

  // recursively hash the first, "remaining" part
  let proof = await Provable.witnessAsync(hashProgram.Proof, async () => {
    // optionally disable the inner proof
    let originalProofsEnabled = hashProgram.proofsEnabled;
    if (!proofsEnabled) hashProgram.setProofsEnabled(false);

    // convert the blocks to constants
    let blocksForProof = Provable.toConstant(MerkleBlocks, remaining.clone());

    // figure out if we can call the base method or need to recurse
    let nBlocksRemaining = remaining.lengthUnconstrained().get();
    console.log({ nBlocksRemaining });
    let proof: Proof<MerkleBlocks, State32>;

    if (nBlocksRemaining <= blocksPerRecursiveProof) {
      console.log('hashBase');
      ({ proof } = await hashProgram.hashBase(blocksForProof));
    } else {
      console.log('hashRecursive');
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

async function verifyEmailRecursive(
  email: ProvableEmail,
  { proofsEnabled = true } = {}
) {
  // 3k constraints to witness the email

  // provable types with max lengths
  let body = DynamicString.from(email.body);
  let header = DynamicString.from(email.header);

  // compute and compare the body hash
  // TODO: this needs a recursive proof
  let bodyHash = Provable.witness(Bytes32, () => body.hashToBytes('sha2-256'));
  // 1.6k constraints
  let bodyHashBase64 = bodyHash.base64Encode();

  // TODO: show that body hash is contained at the correct position from header,
  // using a secure string matching circuit
  // (might be helpful to use the dkim header as hint since it is fairly strictly formatted,
  // and known to come last in the header, and then reassemble with the other headers)

  // TODO: this is just a sanity check and not secure at all
  // 22k constraints  :(
  // header.assertContains(
  //   StaticArray.from(UInt8, bodyHashBase64.bytes),
  //   'verifyEmail: body hash mismatch'
  // );

  // hash the header:

  // pad header into blocks, convert those into a Merkle list, and hash using `hashBlocks()`
  // 3.7k constraints for header length 500
  let headerBlocksDynamic = DynamicSHA2.padding256(header);

  // 200 constraints for header length 500
  let headerBlocks = headerBlocksDynamic.merkelize(DynamicSHA2.commitBlock256);

  // 5.3k constraints per block
  let state = await hashBlocks(headerBlocks, {
    blocksInThisProof: 1,
    blocksPerRecursiveProof: BLOCKS_PER_RECURSIVE_PROOF,
    proofsEnabled,
  });

  // convert final state to bytes
  let headerHash = Bytes32.from(state.array.flatMap((x) => x.toBytesBE()));

  // verify the signature
  // 12k constraints
  rsaVerify65537(headerHash, email.signature, email.publicKey);
}
