import { Bytes } from 'o1js';
import {
  Spec,
  Operation,
  Claim,
  Credential,
  Presentation,
  PresentationRequest,
  assert,
} from '../src/index.ts';
import { issuerKey, owner, ownerKey } from '../tests/test-utils.ts';
import { validateCredential } from '../src/credential-index.ts';

// example schema of the credential, which has enough entropy to be hashed into a unique id
const Bytes32 = Bytes(32);
const Bytes16 = Bytes(16); // 16 bytes = 128 bits = enough entropy

const Data = {
  nationality: Bytes32,
  id: Bytes16,
};

// ---------------------------------------------
// ISSUER: issue a signed credential to the owner
let data = {
  nationality: Bytes32.fromString('United States of America'),
  id: Bytes16.random(),
};
let credential = Credential.sign(issuerKey, { owner, data });
let credentialJson = Credential.toJSON(credential);

console.log('✅ ISSUER: issued credential:', credentialJson);

// ---------------------------------------------
// WALLET: deserialize, validate and store the credential
let storedCredential = Credential.fromJSON(credentialJson);

await validateCredential(storedCredential);

console.log('✅ WALLET: imported and validated credential');

// ---------------------------------------------
// VERIFIER: request a presentation
const spec = Spec(
  {
    signedData: Credential.Simple(Data), // schema needed here!
    targetNationality: Claim(Bytes32),
    appId: Claim(Bytes32),
  },
  ({ signedData, targetNationality, appId }) => ({
    // we assert that the owner has the target nationality
    // TODO: add a one-of-many operation to make this more interesting
    assert: Operation.equals(
      Operation.property(signedData, 'nationality'),
      targetNationality
    ),
    // we expose a unique hash of the credential data, as nullifier
    data: Operation.record({
      nullifier: Operation.hash(signedData, appId),
    }),
  })
);

let request = PresentationRequest.noContext(spec, {
  targetNationality: Bytes32.fromString('United States of America'),
  appId: Bytes32.fromString('my-app-id'),
});
let requestJson = PresentationRequest.toJSON(request);
console.log('✅ VERIFIER: created presentation request:', requestJson);

// ---------------------------------------------
// WALLET: deserialize request and create presentation
console.time('compile');
let deserialized = PresentationRequest.fromJSON<typeof request>(requestJson);
let compiled = await Presentation.compile(deserialized);
console.timeEnd('compile');

console.time('create');
let presentation = await Presentation.create(ownerKey, {
  request: compiled,
  credentials: [storedCredential],
});
console.timeEnd('create');
// TODO: to send the presentation back we need to serialize it as well
console.log('✅ WALLET: created presentation:', presentation);

// ---------------------------------------------
// VERIFIER: verify the presentation, and check that the nullifier was not used yet
let existingNullifiers = new Set([0x13c43f30n, 0x370f3473n, 0xe1fe0cdan]);

// TODO: claims and other I/O values should be plain JS types
let { nullifier } = presentation.outputClaim;
assert(
  !existingNullifiers.has(nullifier.toBigInt()),
  'Nullifier should be unique'
);
console.log('✅ VERIFIER: checked nullifier uniqueness');

// TODO: implement verification
