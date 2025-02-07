import { Field, UInt64 } from 'o1js';
import {
  Claim,
  Credential,
  DynamicRecord,
  Operation,
  Presentation,
  PresentationRequest,
  Spec,
  assert,
} from '../../../src/index.ts';
import { getPublicKey } from './keys.ts';
import { ORIGIN, SERVER_ID } from './config.ts';
import { queuePromise } from './async-queue.ts';

export { requestLogin, verifyLogin };

const ACTION_ID = `${SERVER_ID}:anonymous-login`;

// use a `DynamicRecord` to allow more fields in the credential than we explicitly list
// here, we ONLY care about whether the user has a valid credential issued by this server
const Schema = DynamicRecord({ expiresAt: UInt64 }, { maxEntries: 20 });

const authenticationSpec = Spec(
  {
    credential: Credential.Native(Schema),
    expectedIssuer: Claim(Field),
    createdAt: Claim(UInt64),
  },
  ({ credential, expectedIssuer, createdAt }) => {
    // extract properties from the credential
    let issuer = Operation.issuer(credential);
    let expiresAt = Operation.property(credential, 'expiresAt');

    // we assert that:
    // - the credential issuer matches the expected (public) input, i.e. this server
    // - the credential is not expired (by comparing with the current date)
    return {
      assert: Operation.and(
        Operation.equals(issuer, expectedIssuer),
        Operation.lessThanEq(createdAt, expiresAt)
      ),
    };
  }
);

// set off compiling of the request -- this promise is needed when verifying
let compiledRequestPromise = queuePromise(() =>
  Presentation.precompile(authenticationSpec)
);
compiledRequestPromise.then(() =>
  console.log(`Compiled request after ${performance.now().toFixed(2)}ms`)
);

const openRequests = new Map<string, Request>();

async function createRequest(createdAt: UInt64) {
  let expectedIssuer = Credential.Native.issuer(getPublicKey());
  let compiled = await compiledRequestPromise;

  let request = PresentationRequest.httpsFromCompiled(
    compiled,
    { expectedIssuer, createdAt },
    { action: ACTION_ID }
  );
  openRequests.set(request.inputContext.serverNonce.toString(), request as any);
  return request;
}

type Request = Awaited<ReturnType<typeof createRequest>>;

async function requestLogin() {
  let request = await createRequest(UInt64.from(Date.now()));
  return PresentationRequest.toJSON(request);
}

async function verifyLogin(presentationJson: string) {
  let presentation = Presentation.fromJSON(presentationJson);
  let nonce = presentation.serverNonce.toString();
  let request = openRequests.get(nonce);
  if (!request) throw Error('Unknown presentation');

  // date must be within 5 minutes of the current date
  let createdAt = Number(request.claims.createdAt);
  assert(createdAt > Date.now() - 5 * 60 * 1000, 'Expired presentation');

  // verify the presentation
  await Presentation.verify(request, presentation, {
    verifierIdentity: ORIGIN,
  });

  openRequests.delete(nonce);
}
