import {
  Field,
  type JsonProof,
  Poseidon,
  PrivateKey,
  Provable,
  PublicKey,
  Signature,
  Struct,
  VerificationKey,
  verify,
} from 'o1js';
import { Spec, type Input, type Claims } from './program-spec.ts';
import { createProgram, type Program } from './program.ts';
import {
  hashCredential,
  signCredentials,
  type CredentialSpec,
  type StoredCredential,
} from './credential.ts';
import { assert, isSubclass, zip } from './util.ts';
import { generateContext, computeContext } from './context.ts';
import { NestedProvable } from './nested.ts';
import {
  convertSpecToSerializable,
  serializeInputContext,
} from './serialize.ts';
import {
  convertSpecFromSerializable,
  deserializeInputContext,
} from './deserialize.ts';
import {
  deserializeNestedProvableValue,
  deserializeProvable,
  serializeNestedProvableValue,
  serializeProvable,
} from './serialize-provable.ts';
import { DynamicRecord } from './credentials/dynamic-record.ts';

// external API
export { PresentationRequest, Presentation };

// internal
export {
  type ZkAppInputContext,
  type HttpsInputContext,
  type WalletDerivedContext,
  ZkAppRequest,
  HttpsRequest,
  hashClaims,
};

type PresentationRequestType = 'no-context' | 'zk-app' | 'https';

type WalletDerivedContext = {
  vkHash: Field;
  claims: Field;
  clientNonce: Field;
};

type PresentationRequest<
  RequestType extends PresentationRequestType = PresentationRequestType,
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>,
  InputContext = any,
  WalletContext = any
> = {
  type: RequestType;
  spec: Spec<Output, Inputs>;
  claims: Claims<Inputs>;
  inputContext: InputContext;
  program?: unknown;

  deriveContext(
    /**
     * Context that is passed in from the input request / server-side
     */
    inputContext: InputContext,
    /**
     * Application-specific context that is passed in from the wallet / client-side
     */
    walletContext: WalletContext,
    /**
     * Context automatically (re-)derived on the client
     */
    derivedContext: WalletDerivedContext
  ): Field;
};

const PresentationRequest = {
  https<Output, Inputs extends Record<string, Input>>(
    spec: Spec<Output, Inputs>,
    claims: Claims<Inputs>,
    context: { action: string }
  ) {
    // generate random nonce on "the server"
    let serverNonce = Field.random();

    return HttpsRequest({
      spec,
      claims,
      program: createProgram(spec),
      inputContext: { type: 'https', ...context, serverNonce },
    });
  },

  zkApp<Output, Inputs extends Record<string, Input>>(
    spec: Spec<Output, Inputs>,
    claims: Claims<Inputs>,
    context: { action: Field }
  ) {
    // generate random nonce on "the server"
    let serverNonce = Field.random();

    return ZkAppRequest({
      spec,
      claims,
      program: createProgram(spec),
      inputContext: { type: 'zk-app', ...context, serverNonce },
    });
  },

  noContext<Output, Inputs extends Record<string, Input>>(
    spec: Spec<Output, Inputs>,
    claims: Claims<Inputs>
  ): NoContextRequest<Output, Inputs> {
    return {
      type: 'no-context',
      spec,
      claims,
      inputContext: undefined,
      deriveContext: () => Field(0),
    };
  },

  toJSON(request: PresentationRequest) {
    let json = {
      type: request.type,
      spec: convertSpecToSerializable(request.spec),
      claims: serializeNestedProvableValue(request.claims),
      inputContext: serializeInputContext(request.inputContext),
    };
    return JSON.stringify(json);
  },

  fromJSON<
    R extends RequestFromType<K>,
    K extends PresentationRequestType = PresentationRequestType
  >(expectedType: K, json: string): R {
    let parsed = JSON.parse(json);
    let request = requestFromJson(parsed);
    assert(
      request.type === expectedType,
      `Expected ${expectedType} request, got ${request.type}`
    );
    return request as any;
  },
};

function requestFromJson(
  request: { type: PresentationRequestType } & Record<string, any>
) {
  let spec = convertSpecFromSerializable(request.spec);
  let claims = deserializeNestedProvableValue(request.claims);

  switch (request.type) {
    case 'no-context':
      return PresentationRequest.noContext(spec, claims);
    case 'zk-app': {
      const inputContext: any = deserializeInputContext(request.inputContext);
      return ZkAppRequest({ spec, claims, inputContext });
    }
    case 'https': {
      const inputContext: any = deserializeInputContext(request.inputContext);
      return HttpsRequest({ spec, claims, inputContext });
    }
    default:
      throw Error(`Invalid presentation request type: ${request.type}`);
  }
}

type Presentation<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = {
  version: 'v0';
  claims: Claims<Inputs>;
  outputClaim: Output;
  clientNonce: Field;
  proof: { proof: string; maxProofsVerified: number };
};

type Output<R> = R extends PresentationRequest<any, infer O> ? O : never;
type Inputs<R> = R extends PresentationRequest<any, any, infer I> ? I : never;
type WalletContext<R> = R extends PresentationRequest<
  any,
  any,
  any,
  any,
  infer W
>
  ? W
  : never;

const Presentation = {
  async compile<R extends PresentationRequest>(
    request: R
  ): Promise<
    Omit<R, 'program'> & {
      program: Program<Output<R>, Inputs<R>>;
      verificationKey: VerificationKey;
    }
  > {
    let program: Program<Output<R>, Inputs<R>> = (request as any).program ??
    createProgram(request.spec);
    let verificationKey = await program.compile();
    return { ...request, program, verificationKey };
  },

  /**
   * Create a presentation, given the request, context, and credentials.
   *
   * The first argument is the private key of the credential's owner, which is needed to sign credentials.
   */
  create: createPresentation,

  /**
   * Prepare a presentation, given the request, context, and credentials
   *
   * This way creating the presentation doesn't requre the private key of the owner but instead lets
   * the wallet to handle the signing process
   */
  prepare: preparePresentation,

  /**
   * Finalize presentation given request, signature and prepared data from preparePresentation
   */
  finalize: finalizePresentation,

  /**
   * Verify a presentation against a request and context.
   *
   * Returns the verified output claim of the proof, to be consumed by application-specific logic.
   */
  verify: verifyPresentation,

  /**
   * Serialize a presentation to JSON.
   */
  toJSON,

  /**
   * Deserialize a presentation from JSON.
   */
  fromJSON,
};

async function createPresentation<R extends PresentationRequest>(
  ownerKey: PrivateKey,
  {
    request,
    context: walletContext,
    credentials,
  }: {
    request: R;
    context: WalletContext<R>;
    credentials: (StoredCredential & { key?: string })[];
  }
): Promise<Presentation<Output<R>, Inputs<R>>> {
  // compile the program
  let { program, verificationKey } = await Presentation.compile(request);

  // generate random client nonce
  let clientNonce = Field.random();

  // derive context
  let context = request.deriveContext(request.inputContext, walletContext, {
    clientNonce,
    vkHash: verificationKey.hash,
    claims: hashClaims(request.claims),
  });

  // find credentials and sign with owner key
  let credentialsNeeded = Object.entries(request.spec.inputs).filter(
    (c): c is [string, CredentialSpec] => c[1].type === 'credential'
  );
  let credentialsUsed = pickCredentials(
    credentialsNeeded.map(([key]) => key),
    credentials
  );
  let credentialsAndTypes = credentialsNeeded.map(([key, credentialType]) => {
    let credentialAndType = { ...credentialsUsed[key]!, credentialType };

    // if the credential uses a subschema, we have to wrap it inside DynamicRecord
    if (isSubclass(credentialType.data, DynamicRecord.Base)) {
      let { owner, data } = credentialAndType.credential;
      credentialAndType.credential = {
        owner,
        data: credentialType.data.from(data),
      };
    }
    return credentialAndType;
  });
  let ownerSignature = signCredentials(
    ownerKey,
    context,
    ...credentialsAndTypes
  );

  // create the presentation proof
  let proof = await program.run({
    context,
    claims: request.claims as any,
    ownerSignature,
    credentials: credentialsUsed as any,
  });
  let { proof: proofBase64, maxProofsVerified } = proof.toJSON();

  return {
    version: 'v0',
    claims: request.claims as any,
    outputClaim: proof.publicOutput,
    clientNonce,
    proof: { maxProofsVerified, proof: proofBase64 },
  };
}

async function preparePresentation<R extends PresentationRequest>({
  request,
  context: walletContext,
  credentials,
}: {
  request: R;
  context: WalletContext<R>;
  credentials: (StoredCredential & { key?: string })[];
}): Promise<{
  context: Field;
  fields: string[];
  credentialsUsed: Record<string, StoredCredential>;
  clientNonce: Field;
  compiledRequest: {
    program: Program<Output<R>, Inputs<R>>;
    verificationKey: VerificationKey;
  };
}> {
  let { program, verificationKey } = await Presentation.compile(request);
  let clientNonce = Field.random();
  let context = request.deriveContext(request.inputContext, walletContext, {
    clientNonce,
    vkHash: verificationKey.hash,
    claims: hashClaims(request.claims),
  });

  let credentialsNeeded = Object.entries(request.spec.inputs).filter(
    (c): c is [string, CredentialSpec] => c[1].type === 'credential'
  );
  let credentialsUsed = pickCredentials(
    credentialsNeeded.map(([key]) => key),
    credentials
  );
  let credentialsAndTypes = credentialsNeeded.map(([key, credentialType]) => {
    let credentialAndType = { ...credentialsUsed[key]!, credentialType };
    if (isSubclass(credentialType.data, DynamicRecord.Base)) {
      let { owner, data } = credentialAndType.credential;
      credentialAndType.credential = {
        owner,
        data: credentialType.data.from(data),
      };
    }
    return credentialAndType;
  });

  let credHashes = credentialsAndTypes.map(({ credentialType, credential }) =>
    hashCredential(credentialType.data, credential)
  );
  let issuers = credentialsAndTypes.map(({ credentialType, witness }) =>
    credentialType.issuer(witness)
  );

  const fieldsToSign = [
    context,
    ...zip(
      credHashes.map((c) => c.hash),
      issuers
    ).flat(),
  ];
  const msg = fieldsToSign.toString();
  return {
    context,
    fields: fieldsToSign.map((f) => f.toString()),
    credentialsUsed,
    clientNonce,
    compiledRequest: { program, verificationKey },
  };
}

async function finalizePresentation<R extends PresentationRequest>(
  request: R,
  ownerSignature: Signature,
  preparedData: {
    clientNonce: Field;
    context: Field;
    credentialsUsed: Record<string, StoredCredential>;
    compiledRequest: { program: Program<Output<R>, Inputs<R>> };
  }
): Promise<Presentation<Output<R>, Inputs<R>>> {
  let proof = await preparedData.compiledRequest.program.run({
    context: preparedData.context,
    claims: request.claims as any,
    ownerSignature,
    credentials: preparedData.credentialsUsed as any,
  });
  let { proof: proofBase64, maxProofsVerified } = proof.toJSON();

  return {
    version: 'v0',
    claims: request.claims as any,
    outputClaim: proof.publicOutput,
    clientNonce: preparedData.clientNonce,
    proof: { maxProofsVerified, proof: proofBase64 },
  };
}

async function createPresentationPrepareFinalize<R extends PresentationRequest>(
  ownerKey: PrivateKey,
  params: {
    request: R;
    context: WalletContext<R>;
    credentials: (StoredCredential & { key?: string })[];
  }
): Promise<Presentation<Output<R>, Inputs<R>>> {
  const prepared = await preparePresentation(params);
  const ownerSignature = Signature.create(
    ownerKey,
    prepared.fields.map(Field.from)
  );
  return finalizePresentation(params.request, ownerSignature, prepared);
}

async function verifyPresentation<R extends PresentationRequest>(
  request: R,
  presentation: Presentation<any, Record<string, any>>,
  context: WalletContext<R>
): Promise<Output<R>> {
  // make sure request is compiled
  let { program, verificationKey } = await Presentation.compile(request);

  // rederive context
  let contextHash = request.deriveContext(request.inputContext, context, {
    clientNonce: presentation.clientNonce,
    vkHash: verificationKey.hash,
    claims: hashClaims(request.claims),
  });

  // assert the correct claims were used, and claims match the proof public inputs
  let { proof, outputClaim } = presentation;
  let claimType = NestedProvable.get(NestedProvable.fromValue(request.claims));
  let claims = request.claims;
  Provable.assertEqual(claimType, presentation.claims, claims);

  // reconstruct proof object
  let inputType = program.program.publicInputType;
  let outputType = program.program.publicOutputType;
  let publicInputFields = inputType.toFields({
    context: contextHash,
    claims: claims as any,
  });
  let publicOutputFields = outputType.toFields(outputClaim);
  let jsonProof: JsonProof = {
    publicInput: publicInputFields.map((f) => f.toString()),
    publicOutput: publicOutputFields.map((f) => f.toString()),
    proof: proof.proof,
    maxProofsVerified: proof.maxProofsVerified as 0 | 1 | 2,
  };

  // verify the proof against our verification key
  let ok = await verify(jsonProof, verificationKey);
  assert(ok, 'Invalid proof');

  // return the verified outputClaim
  return outputClaim;
}

function toJSON<Output, Inputs extends Record<string, Input>>(
  presentation: Presentation<Output, Inputs>
): string {
  let json = {
    version: presentation.version,
    claims: serializeNestedProvableValue(presentation.claims),
    outputClaim: serializeNestedProvableValue(presentation.outputClaim),
    clientNonce: serializeProvable(presentation.clientNonce),
    proof: presentation.proof,
  };
  return JSON.stringify(json);
}

function fromJSON(presentationJson: string): Presentation {
  let presentation = JSON.parse(presentationJson);
  assert(
    presentation.version === 'v0',
    `Unsupported presentation version: ${presentation.version}`
  );

  return {
    version: presentation.version,
    claims: deserializeNestedProvableValue(presentation.claims),
    outputClaim: deserializeNestedProvableValue(presentation.outputClaim),
    clientNonce: deserializeProvable(presentation.clientNonce),
    proof: presentation.proof,
  };
}

// helper

function pickCredentials(
  credentialsNeeded: string[],
  [...credentials]: (StoredCredential & { key?: string })[]
): Record<string, StoredCredential> {
  let credentialsUsed: Record<string, StoredCredential> = {};
  let credentialsStillNeeded: string[] = [];

  for (let key of credentialsNeeded) {
    let i = credentials.findIndex((c) => c.key === key);
    if (i === -1) {
      credentialsStillNeeded.push(key);
      continue;
    } else {
      credentialsUsed[key] = credentials[i]!;
      credentials.splice(i, 1);
    }
  }
  let i = 0;
  for (let credential of credentials) {
    if (credentialsStillNeeded.length === 0) break;
    credentialsUsed[credentialsStillNeeded.shift()!] = credential;
    i++;
  }
  assert(
    credentialsStillNeeded.length === 0,
    `Missing credentials: ${credentialsStillNeeded.join(', ')}`
  );
  return credentialsUsed;
}

// specific types of requests

type RequestFromType<
  Type extends PresentationRequestType,
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = Type extends 'no-context'
  ? NoContextRequest<Output, Inputs>
  : Type extends 'zk-app'
  ? ZkAppRequest<Output, Inputs>
  : Type extends 'https'
  ? HttpsRequest<Output, Inputs>
  : never;

type NoContextRequest<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = PresentationRequest<'no-context', Output, Inputs, undefined, undefined>;

type BaseInputContext = {
  serverNonce: Field;
};

type HttpsInputContext = BaseInputContext & {
  type: 'https';
  action: string;
};

type HttpsRequest<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = PresentationRequest<
  'https',
  Output,
  Inputs,
  HttpsInputContext,
  { verifierIdentity: string }
>;

function HttpsRequest<Output, Inputs extends Record<string, Input>>(request: {
  spec: Spec<Output, Inputs>;
  claims: Claims<Inputs>;
  inputContext: HttpsInputContext;
  program?: Program<Output, Inputs>;
}): HttpsRequest<Output, Inputs> {
  return {
    type: 'https',
    ...request,

    deriveContext(inputContext, walletContext, derivedContext) {
      const context = computeContext({
        ...inputContext,
        ...walletContext,
        ...derivedContext,
      });
      return generateContext(context);
    },
  };
}

type ZkAppInputContext = BaseInputContext & {
  type: 'zk-app';
  action: Field;
};

type ZkAppRequest<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = PresentationRequest<
  'zk-app',
  Output,
  Inputs,
  ZkAppInputContext,
  { verifierIdentity: PublicKey }
>;

function ZkAppRequest<Output, Inputs extends Record<string, Input>>(request: {
  spec: Spec<Output, Inputs>;
  claims: Claims<Inputs>;
  inputContext: ZkAppInputContext;
  program?: Program<Output, Inputs>;
}): ZkAppRequest<Output, Inputs> {
  return {
    type: 'zk-app',
    ...request,

    deriveContext(inputContext, walletContext, derivedContext) {
      const context = computeContext({
        ...inputContext,
        ...walletContext,
        ...derivedContext,
      });
      return generateContext(context);
    },
  };
}

function hashClaims(claims: Claims<any>) {
  let claimsType = NestedProvable.fromValue(claims);
  let claimsFields = Struct(claimsType).toFields(claims);
  return Poseidon.hash(claimsFields);
}
