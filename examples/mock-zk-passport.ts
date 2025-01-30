import {
  Claim,
  Credential,
  DynamicString,
  Operation,
  Presentation,
  PresentationRequest,
  PresentationSpec,
} from 'mina-attestations';
import { owner, ownerKey } from '../tests/test-utils.ts';
import { UInt64 } from 'o1js';

const String = DynamicString({ maxLength: 30 });

let PassportCredential = await Credential.Recursive.fromMethod(
  {
    name: 'passport',
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
  publicInput: undefined,
  privateInput: {
    expiresAt: UInt64.from(Date.UTC(2027, 1, 1)),
    nationality: 'Austria',
  },
});

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

let presentation = await Presentation.create(ownerKey, {
  request,
  credentials: [cred],
  context: { verifierIdentity: 'crypto-exchange.com' },
});

let output = await Presentation.verify(request, presentation, {
  verifierIdentity: 'crypto-exchange.com',
});

// TODO verify issuer
console.log('issuer', output);
