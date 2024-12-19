import { Bytes, Field, PublicKey, UInt64 } from 'o1js';
import {
  Claim,
  Credential,
  DynamicArray,
  DynamicRecord,
  DynamicString,
  hashDynamic,
  Operation,
  Presentation,
  PresentationRequest,
  Spec,
  HttpsRequest,
} from '../../../src/index.ts';
import { getPublicKey } from './keys.ts';

export { requestLogin, verifyLogin };

const String = DynamicString({ maxLength: 50 });

const Subschema = DynamicRecord(
  { nationality: String, expiresAt: UInt64, id: Bytes(16) },
  { maxEntries: 20 }
);

const FieldArray = DynamicArray(Field, { maxLength: 100 });

const spec = Spec(
  {
    credential: Credential.Simple(Subschema),
    acceptedNations: Claim(FieldArray), // we represent nations as their hashes for efficiency
    expectedIssuer: Claim(Field),
    currentDate: Claim(UInt64),
    actionId: Claim(String),
  },
  ({ credential, acceptedNations, expectedIssuer, currentDate, actionId }) => {
    // extract properties from the credential
    let nationality = Operation.property(credential, 'nationality');
    let issuer = Operation.issuer(credential);
    let expiresAt = Operation.property(credential, 'expiresAt');

    // we assert that:
    // 1. the owner has one of the accepted nationalities
    // 2. the credential issuer matches the expected (public) input
    // 3. the credential is not expired (by comparing with the current date)
    let assert = Operation.and(
      Operation.equalsOneOf(Operation.hash(nationality), acceptedNations),
      Operation.equals(issuer, expectedIssuer),
      Operation.lessThanEq(currentDate, expiresAt)
    );

    // we expose a unique hash of the credential data, to be used as nullifier
    // note: since the credential contains a 16 byte = 128 bit random ID, it has enough
    // entropy such that exposing this hash will not reveal the credential data
    let outputClaim = Operation.record({
      nullifier: Operation.hash(credential, actionId),
    });

    return { assert, outputClaim };
  }
);

const acceptedNations = [
  'United States of America',
  'Canada',
  'Mexico',
  'Austria',
];
const acceptedNationHashes = FieldArray.from(
  acceptedNations.map((s) => hashDynamic(s))
);
const ACTION_ID = 'credentials-web-demo-server:anonymous-login';

// TODO our API design is flawed, need to be able to prepare compiled request template without
// already specifying the public inputs

function createRequest(currentDate: UInt64) {
  let expectedIssuer = Credential.Simple.issuer(getPublicKey());

  return PresentationRequest.https(
    spec,
    {
      acceptedNations: acceptedNationHashes,
      expectedIssuer,
      currentDate,
      actionId: String.from(ACTION_ID),
    },
    { action: ACTION_ID }
  );
}
type Request = ReturnType<typeof createRequest>;
type Output = Request extends HttpsRequest<infer O> ? O : never;
type Inputs = Request extends HttpsRequest<any, infer I> ? I : never;

async function requestLogin() {
  let publicKey = getPublicKey();
  let request = createRequest(UInt64.from(Date.now()));
  return PresentationRequest.toJSON(request);
}

async function verifyLogin(presentationJson: string) {
  let presentation = Presentation.fromJSON(presentationJson) as Presentation<
    Output,
    Inputs
  >;
  // TODO
  let currentDate = presentation.claims.currentDate;
  currentDate.assertGreaterThan(UInt64.from(Date.now() - 1000));
  let request = createRequest(presentation.claims.currentDate);

  await Presentation.verify(request, presentation, {
    verifierIdentity: window.location.hostname,
  });
}