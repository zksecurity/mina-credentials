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
} from '../../../..';
import { getPublicKey, privateKey } from './issue-credential';
import { getStoredCredentials } from './store-credential';

export { requestPresentation, verifyPresentation };

const String = DynamicString({ maxLength: 50 });

const Subschema = DynamicRecord(
  {
    nationality: String,
    expiresAt: UInt64, // we don't have to match the original order of keys
    id: Bytes(16),
  },
  // have to specify maximum number of entries of the original schema
  { maxEntries: 20 }
);

const FieldArray = DynamicArray(Field, { maxLength: 100 });

const spec = Spec(
  {
    credential: Credential.Simple(Subschema),
    acceptedNations: Claim(FieldArray), // we represent nations as their hashes for efficiency
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
      Operation.equalsOneOf(Operation.hash(nationality), acceptedNations),
      Operation.equalsOneOf(issuer, acceptedIssuers),
      Operation.lessThanEq(currentDate, expiresAt)
    );

    // we expose a unique hash of the credential data, to be used as nullifier
    // note: since the credential contains a 16 byte = 128 bit random ID, it has enough
    // entropy such that exposing this hash will not reveal the credential data
    let outputClaim = Operation.record({
      nullifier: Operation.hash(credential, appId),
    });

    return { assert, outputClaim };
  }
);

const acceptedNations = ['United States of America', 'Canada', 'Mexico'];

let request: HttpsRequest | undefined;

async function createRequest(issuer: PublicKey) {
  const acceptedIssuers = [issuer].map((pk) => Credential.Simple.issuer(pk));

  return PresentationRequest.https(
    spec,
    {
      acceptedNations: FieldArray.from(
        acceptedNations.map((s) => hashDynamic(s))
      ),
      acceptedIssuers: FieldArray.from(acceptedIssuers),
      currentDate: UInt64.from(Date.now()),
      appId: String.from('my-app-id:123'),
    },
    { action: 'my-app-id:123:authenticate' }
  );
}

async function requestPresentation(useMockWallet: boolean) {
  let issuer = PublicKey.fromBase58(await getPublicKey(useMockWallet));
  request ??= await createRequest(issuer);
  let requestJson = PresentationRequest.toJSON(request);

  if (!useMockWallet) throw Error('NOT_IMPLEMENTED');
  return createMockPresentation(requestJson);
}

async function verifyPresentation(
  requestJson: string,
  presentationJson: string
) {
  request ??= PresentationRequest.fromJSON('https', requestJson);
  let presentation = Presentation.fromJSON(presentationJson);

  await Presentation.verify(request, presentation, {
    verifierIdentity: window.location.hostname,
  });
}

async function createMockPresentation(requestJson: string) {
  let credentials = await getStoredCredentials(true);

  request ??= PresentationRequest.fromJSON('https', requestJson);
  console.time('compile');
  await Presentation.compile(request);
  console.timeEnd('compile');

  console.time('create');
  let presentation = await Presentation.create(privateKey, {
    request,
    credentials,
    context: { verifierIdentity: window.location.hostname },
  });
  console.timeEnd('create');

  return Presentation.toJSON(presentation);
}
