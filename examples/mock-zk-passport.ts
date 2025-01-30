import {
  Claim,
  Credential,
  DynamicString,
  Operation,
  Presentation,
  PresentationRequest,
  PresentationSpec,
} from '../src/index.ts';
import { owner, ownerKey } from '../tests/test-utils.ts';
import { Field, UInt64 } from 'o1js';

const String = DynamicString({ maxLength: 30 });

let PassportCredential = await Credential.Recursive.fromMethod(
  {
    name: 'passport',
    publicInput: { something: Field },
    privateInput: { nationality: String, expiresAt: UInt64 },
    data: { nationality: String, expiresAt: UInt64 },
  },
  async ({ privateInput }) => {
    return privateInput;
  }
);
// create (dummy) passport credential
let cred = await PassportCredential.create({
  owner,
  publicInput: {
    something: Field(0),
  },
  privateInput: {
    expiresAt: UInt64.from(Date.UTC(2027, 1, 1)),
    nationality: 'Austria',
  },
});
let credJson = Credential.toJSON(cred);
let credRecovered = await Credential.fromJSON(credJson);

let spec = PresentationSpec(
  { passport: PassportCredential.type, createdAt: Claim(UInt64) },
  ({ passport, createdAt }) => {
    const { issuer, property, not, equals, constant, record, lessThanEq } =
      Operation;

    let nationality = property(passport, 'nationality');
    let expiresAt = property(passport, 'expiresAt');

    return {
      assert: [
        not(equals(nationality, constant(String.from('United States')))),
        lessThanEq(createdAt, expiresAt),
      ],
      outputClaim: record({
        issuer: issuer(passport),
      }),
    };
  }
);
let compiledSpec = await Presentation.precompile(spec);

let request = PresentationRequest.httpsFromCompiled(
  compiledSpec,
  { createdAt: UInt64.from(Date.now()) },
  { action: 'verify-citizenship' }
);
let requestJson = PresentationRequest.toJSON(request);

let presentation = await Presentation.create(ownerKey, {
  request: PresentationRequest.fromJSON('https', requestJson),
  credentials: [credRecovered],
  context: { verifierIdentity: 'crypto-exchange.com' },
});
let presentationJson = Presentation.toJSON(presentation);

let output = await Presentation.verify(
  request,
  Presentation.fromJSON(presentationJson),
  {
    verifierIdentity: 'crypto-exchange.com',
  }
);

// TODO verify issuer
console.log('issuer', output);
