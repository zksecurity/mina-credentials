import {
  Claim,
  Credential,
  DynamicString,
  log,
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
    publicInput: { issuer: Field },
    privateInput: { nationality: String, expiresAt: UInt64 },
    data: { nationality: String, expiresAt: UInt64 },
  },
  async ({ privateInput }) => {
    return privateInput;
  }
);
let vk = await PassportCredential.compile();

// create (dummy) passport credential
let cred = await PassportCredential.create({
  owner,
  publicInput: { issuer: 1001 },
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
    let nationality = Operation.property(passport, 'nationality');
    let expiresAt = Operation.property(passport, 'expiresAt');

    return {
      assert: [
        Operation.not(
          Operation.equals(
            nationality,
            Operation.constant(String.from('United States'))
          )
        ),

        // passport is not expired
        Operation.lessThanEq(createdAt, expiresAt),

        // hard-code passport verification key
        Operation.equals(
          Operation.verificationKeyHash(passport),
          Operation.constant(vk.hash)
        ),
      ],
      // return public input (passport issuer hash) for verification
      outputClaim: Operation.publicInput(passport),
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
log('issuer', output);
