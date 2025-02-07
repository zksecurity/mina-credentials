import {
  assert,
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

const Nationality = DynamicString({ maxLength: 50 });

// dummy passport credential, which just takes in some data and returns it
// TODO: in place of this, we'd want a real proof of passport verification
// (implementation in progress at the time of writing)
let PassportCredential_ = await Credential.Imported.fromMethod(
  {
    name: 'passport',
    publicInput: { issuer: Field },
    privateInput: { nationality: Nationality, expiresAt: UInt64 },
    data: { nationality: Nationality, expiresAt: UInt64 },
  },
  async ({ privateInput }) => {
    return privateInput;
  }
);
let PassportCredential = Object.assign(PassportCredential_, { Nationality });
let vk = await PassportCredential.compile();

// user "imports" their passport into a credential, by creating a PassportCredential proof
let cred = await PassportCredential.create({
  owner,
  publicInput: { issuer: 1001 },
  privateInput: {
    expiresAt: UInt64.from(Date.UTC(2027, 1, 1)),
    nationality: 'Austria',
  },
});
await Credential.validate(cred);
let credJson = Credential.toJSON(cred);

/**
 * Presentation spec for using a passport credential to verify
 * that the user is a citizen from a country other than the United States.
 */
let spec = PresentationSpec(
  { passport: PassportCredential.spec, createdAt: Claim(UInt64) },
  ({ passport, createdAt }) => ({
    assert: [
      // not from the United States
      Operation.not(
        Operation.equals(
          Operation.property(passport, 'nationality'),
          Operation.constant(
            PassportCredential.Nationality.from('United States')
          )
        )
      ),

      // passport is not expired
      Operation.lessThanEq(
        createdAt,
        Operation.property(passport, 'expiresAt')
      ),

      // hard-code passport verification key
      Operation.equals(
        Operation.verificationKeyHash(passport),
        Operation.constant(vk.hash)
      ),
    ],
    // return public input (passport issuer hash) for verification
    outputClaim: Operation.publicInput(passport),
  })
);
let compiledSpec = await Presentation.precompile(spec);

// based on the (precompiled) spec, the verifier creates a presentation request
let request = PresentationRequest.httpsFromCompiled(
  compiledSpec,
  { createdAt: UInt64.from(Date.now()) },
  { action: 'verify-citizenship' }
);
let requestJson = PresentationRequest.toJSON(request);

// the user answers the request by creating a presentation from their passport credential
let recoveredCredential = await Credential.fromJSON(credJson);
let recoveredRequest = PresentationRequest.fromJSON('https', requestJson);

let presentation = await Presentation.create(ownerKey, {
  request: recoveredRequest,
  credentials: [recoveredCredential],
  context: { verifierIdentity: 'crypto-exchange.com' },
});
let presentationJson = Presentation.toJSON(presentation);

// the verifier verifies the presentation against their own (stored) request
let output = await Presentation.verify(
  request,
  Presentation.fromJSON(presentationJson),
  { verifierIdentity: 'crypto-exchange.com' }
);
// also need to verify that the passport was issued by a legitimate authority.
// to enable this, the passport presentation exposed the `issuer` (public input of the passport credential)
let acceptedIssuers = [1001n, 1203981n, 21380123n]; // mocked list of accepted issuers
assert(acceptedIssuers.includes(output.issuer.toBigInt()), 'Invalid issuer');
