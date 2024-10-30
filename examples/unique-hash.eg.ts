import { Bytes, Field, UInt64 } from 'o1js';
import {
  Spec,
  Operation,
  Claim,
  Credential,
  Presentation,
  PresentationRequest,
  assert,
  type InferSchema,
  DynamicString,
  DynamicArray,
} from '../src/index.ts';
import {
  issuer,
  issuerKey,
  owner,
  ownerKey,
  randomPublicKey,
} from '../tests/test-utils.ts';

// example schema of the credential, which has enough entropy to be hashed into a unique id
const String = DynamicString({ maxLength: 50 });
const Bytes16 = Bytes(16);

const Schema = {
  /**
   * Nationality of the owner.
   */
  nationality: String,

  /**
   * Owner ID (16 bytes).
   */
  id: Bytes16,

  /**
   * Timestamp when the credential expires.
   */
  expiresAt: UInt64,
};

// ---------------------------------------------
// ISSUER: issue a signed credential to the owner

let data: InferSchema<typeof Schema> = {
  nationality: String.from('United States of America'),
  id: Bytes16.random(),
  expiresAt: UInt64.from(Date.UTC(2028, 7, 1)),
};
let credential = Credential.sign(issuerKey, { owner, data });
let credentialJson = Credential.toJSON(credential);

console.log('✅ ISSUER: issued credential:', credentialJson);

// ---------------------------------------------
// WALLET: deserialize, validate and store the credential

let storedCredential = Credential.fromJSON(credentialJson);

await Credential.validate(storedCredential);

console.log('✅ WALLET: imported and validated credential');

// ---------------------------------------------
// VERIFIER: request a presentation

const StringArray = DynamicArray(String, { maxLength: 20 });
const FieldArray = DynamicArray(Field, { maxLength: 20 });

const spec = Spec(
  {
    credential: Credential.Simple(Schema), // schema needed here!
    acceptedNations: Claim(StringArray),
    acceptedIssuers: Claim(FieldArray),
    currentDate: Claim(UInt64),
    appId: Claim(String),
  },
  ({ credential, acceptedNations, acceptedIssuers, currentDate, appId }) => {
    // extract properties from the credential
    let nationality = Operation.property(credential, 'nationality');
    let issuer = Operation.issuer(credential);
    let expiresAt = Operation.property(credential, 'expiresAt');

    // we assert that:
    // 1. the owner has one of the accepted nationalities
    // 2. the credential was issued by one of the accepted issuers
    // 3. the credential is not expired (by comparing with the current date)
    let assert = Operation.and(
      Operation.equalsOneOf(nationality, acceptedNations),
      Operation.equalsOneOf(issuer, acceptedIssuers),
      Operation.lessThanEq(currentDate, expiresAt)
    );

    // we expose a unique hash of the credential data, to be used as nullifier
    // note: since the credential contains a 16 byte = 128 bit random ID, it has enough
    // entropy such that exposing this hash will not reveal the credential data
    let ouputClaim = Operation.record({
      nullifier: Operation.hash(credential, appId),
    });

    return { assert, ouputClaim };
  }
);

const acceptedNations = ['United States of America', 'Canada', 'Mexico'];
const acceptedIssuers = [issuer, randomPublicKey(), randomPublicKey()].map(
  (pk) => Credential.Simple.issuer(pk)
);

let request = PresentationRequest.https(
  spec,
  {
    acceptedNations: StringArray.from(acceptedNations),
    acceptedIssuers: FieldArray.from(acceptedIssuers),
    currentDate: UInt64.from(Date.now()),
    appId: String.from('my-app-id:123'),
  },
  { action: 'my-app-id:123:authenticate' }
);
let requestJson = PresentationRequest.toJSON(request);

console.log(
  '✅ VERIFIER: created presentation request:',
  requestJson.slice(0, 500) + '...'
);

// ---------------------------------------------
// WALLET: deserialize request and create presentation

console.time('compile');
let deserialized = PresentationRequest.fromJSON('https', requestJson);
let compiled = await Presentation.compile(deserialized);
console.timeEnd('compile');

console.time('create');
let presentation = await Presentation.create(ownerKey, {
  request: compiled,
  credentials: [storedCredential],
  context: { verifierIdentity: 'my-app.xyz' },
});
console.timeEnd('create');

let serialized = Presentation.toJSON(presentation);
console.log(
  '✅ WALLET: created presentation:',
  serialized.slice(0, 2000) + '...'
);

// ---------------------------------------------
// VERIFIER: verify the presentation against the request we submitted, and check that the nullifier was not used yet

let presentation2 = Presentation.fromJSON(serialized);

let outputClaim = await Presentation.verify(request, presentation2, {
  verifierIdentity: 'my-app.xyz',
});
console.log('✅ VERIFIER: verified presentation');

let existingNullifiers = new Set([0x13c43f30n, 0x370f3473n, 0xe1fe0cdan]);

let { nullifier } = outputClaim;
assert(
  !existingNullifiers.has(nullifier.toBigInt()),
  'Nullifier should be unique'
);
console.log('✅ VERIFIER: checked nullifier uniqueness');
