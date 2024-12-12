import { record, z } from 'zod';
import type { JSONValue } from '../types.ts';

export {
  StoredCredentialSchema,
  PresentationRequestSchema,
  NodeSchema,
  InputSchema,
  ContextSchema,
};

type SerializedFactory = {
  _type: string;
  _isFactory: true;
} & Serialized;

type Serialized = Record<string, any>;

type O1jsTypeName =
  | 'PublicKey'
  | 'Signature'
  | 'Field'
  | 'Bool'
  | 'UInt8'
  | 'UInt32'
  | 'UInt64'
  | 'Undefined'
  | 'VerificationKey';

type SerializedType =
  | { _type: O1jsTypeName }
  | { _type: 'Struct'; properties: SerializedNestedType }
  | { _type: 'Array'; inner: SerializedType; size: number }
  | { _type: 'Constant'; value: JSONValue }
  | { _type: 'Bytes'; size: number }
  | { _type: 'Proof'; proof: Record<string, any> }
  | { _type: 'String' }
  | SerializedFactory;

type SerializedNestedType =
  | SerializedType
  | { [key: string]: SerializedNestedType };

type Literal = string | number | boolean | null;
type Json = Literal | { [key: string]: Json } | Json[];

const LiteralSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]);

const JsonSchema: z.ZodType<Json> = z.lazy(() =>
  z.union([LiteralSchema, z.array(JsonSchema), z.record(JsonSchema)])
);

const PublicKeySchema = z.string().length(55).startsWith('B62');

const ProofTypeSchema: z.ZodType<Record<string, any>> = z.lazy(() =>
  z
    .object({
      name: z.string(),
      publicInput: SerializedTypeSchema,
      publicOutput: SerializedTypeSchema,
      maxProofsVerified: z.number(),
      featureFlags: z.record(z.any()),
    })
    .strict()
);

const SerializedTypeSchema: z.ZodType<SerializedType> = z.lazy(() =>
  z.union([
    // Basic type
    z.object({
      _type: z.union([
        z.literal('Field'),
        z.literal('Bool'),
        z.literal('UInt8'),
        z.literal('UInt32'),
        z.literal('UInt64'),
        z.literal('PublicKey'),
        z.literal('Signature'),
        z.literal('Undefined'),
        z.literal('VerificationKey'),
      ]),
    }),
    // Constant type
    z.object({
      _type: z.literal('Constant'),
      value: JsonSchema,
    }),
    // Bytes type
    z.object({
      _type: z.literal('Bytes'),
      size: z.number(),
    }),
    // Proof type
    z.object({
      _type: z.literal('Proof'),
      proof: ProofTypeSchema,
    }),
    // Array type
    z.object({
      _type: z.literal('Array'),
      inner: SerializedTypeSchema,
      size: z.number(),
    }),
    // Struct type
    z.object({
      _type: z.literal('Struct'),
      properties: record(NestedSerializedTypeSchema),
    }),
    // Factory
    z.object({
      _type: z.string(),
      _isFactory: z.literal(true),
      maxLength: z.number().optional(),
      maxEntries: z.number().optional(),
      innerType: z.lazy(() => SerializedTypeSchema).optional(),
      knownShape: z.record(z.lazy(() => SerializedTypeSchema)).optional(),
    }),
  ])
);

const NestedSerializedTypeSchema: z.ZodType<SerializedNestedType> = z.lazy(() =>
  z.union([z.record(NestedSerializedTypeSchema), SerializedTypeSchema])
);

const SerializedValueSchema = SerializedTypeSchema.and(
  z.object({ value: JsonSchema })
);

const SerializedDataValueSchema = z.union([
  SerializedValueSchema,
  z.string(),
  z.number(),
  z.boolean(),
]);

const SerializedFieldSchema = z
  .object({
    _type: z.literal('Field'),
    value: z.string(),
  })
  .strict();

const SerializedPublicKeySchema = z
  .object({
    _type: z.literal('PublicKey'),
    value: z.string(),
  })
  .strict();

const SerializedPublicKeyTypeSchema = z
  .object({
    _type: z.literal('PublicKey'),
  })
  .strict();

const SerializedSignatureSchema = z
  .object({
    _type: z.literal('Signature'),
    value: z.object({
      r: z.string(),
      s: z.string(),
    }),
  })
  .strict();

// Node schemas
type Node =
  | { type: 'owner' }
  | { type: 'issuer'; credentialKey: string }
  | { type: 'constant'; data: z.infer<typeof SerializedValueSchema> }
  | { type: 'root' }
  | { type: 'property'; key: string; inner: Node }
  | { type: 'record'; data: Record<string, Node> }
  | { type: 'equals'; left: Node; right: Node }
  | { type: 'equalsOneOf'; input: Node; options: Node[] | Node }
  | { type: 'lessThan'; left: Node; right: Node }
  | { type: 'lessThanEq'; left: Node; right: Node }
  | { type: 'add'; left: Node; right: Node }
  | { type: 'sub'; left: Node; right: Node }
  | { type: 'mul'; left: Node; right: Node }
  | { type: 'div'; left: Node; right: Node }
  | { type: 'and'; inputs: Node[] }
  | { type: 'or'; left: Node; right: Node }
  | { type: 'not'; inner: Node }
  | { type: 'hash'; inputs: Node[]; prefix?: string | null }
  | { type: 'ifThenElse'; condition: Node; thenNode: Node; elseNode: Node };

const NodeSchema: z.ZodType<Node> = z.lazy(() =>
  z.discriminatedUnion('type', [
    z
      .object({
        type: z.literal('owner'),
      })
      .strict(),

    z
      .object({
        type: z.literal('issuer'),
        credentialKey: z.string(),
      })
      .strict(),

    z
      .object({
        type: z.literal('constant'),
        data: SerializedValueSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('root'),
      })
      .strict(),

    z
      .object({
        type: z.literal('property'),
        key: z.string(),
        inner: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('record'),
        data: z.record(NodeSchema),
      })
      .strict(),

    z
      .object({
        type: z.literal('equals'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('equalsOneOf'),
        input: NodeSchema,
        options: z.union([
          z.array(NodeSchema), // For array of nodes case
          NodeSchema,
        ]),
      })
      .strict(),

    z
      .object({
        type: z.literal('lessThan'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('lessThanEq'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('add'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('sub'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('mul'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('div'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('and'),
        inputs: z.array(NodeSchema),
      })
      .strict(),

    z
      .object({
        type: z.literal('or'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('not'),
        inner: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('hash'),
        inputs: z.array(NodeSchema),
        prefix: z.union([z.string(), z.null()]).optional(),
      })
      .strict(),

    z
      .object({
        type: z.literal('ifThenElse'),
        condition: NodeSchema,
        thenNode: NodeSchema,
        elseNode: NodeSchema,
      })
      .strict(),
  ])
);

// Input Schema

const InputSchema = z.discriminatedUnion('type', [
  z
    .object({
      type: z.literal('credential'),
      credentialType: z.union([
        z.literal('simple'),
        z.literal('unsigned'),
        z.literal('recursive'),
      ]),
      witness: NestedSerializedTypeSchema,
      data: NestedSerializedTypeSchema,
    })
    .strict(),

  z
    .object({
      type: z.literal('constant'),
      data: SerializedTypeSchema,
      value: JsonSchema,
    })
    .strict(),

  z
    .object({
      type: z.literal('claim'),
      data: NestedSerializedTypeSchema,
    })
    .strict(),
]);

// Context schemas

const HttpsContextSchema = z
  .object({
    type: z.literal('https'),
    action: z.string(),
    serverNonce: SerializedFieldSchema,
  })
  .strict();

const ZkAppContextSchema = z
  .object({
    type: z.literal('zk-app'),
    action: SerializedFieldSchema,
    serverNonce: SerializedFieldSchema,
  })
  .strict();

const ContextSchema = z.union([HttpsContextSchema, ZkAppContextSchema]);

const PresentationRequestSchema = z
  .object({
    type: z.union([
      z.literal('no-context'),
      z.literal('zk-app'),
      z.literal('https'),
    ]),
    spec: z
      .object({
        inputs: z.record(InputSchema),
        logic: z
          .object({
            assert: NodeSchema,
            outputClaim: NodeSchema,
          })
          .strict(),
      })
      .strict(),
    claims: z.record(SerializedValueSchema),
    inputContext: z.union([ContextSchema, z.null()]),
  })
  .strict();

// Witness Schemas

const SimpleWitnessSchema = z
  .object({
    type: z.literal('simple'),
    issuer: SerializedPublicKeySchema,
    issuerSignature: SerializedSignatureSchema,
  })
  .strict();

const RecursiveWitnessSchema = z
  .object({
    type: z.literal('recursive'),
    vk: z
      .object({
        data: z.string(),
        hash: SerializedFieldSchema,
      })
      .strict(),
    proof: z
      .object({
        _type: z.literal('Proof'),
        proof: ProofTypeSchema,
        value: z
          .object({
            publicInput: JsonSchema,
            publicOutput: JsonSchema,
            maxProofsVerified: z.number().min(0).max(2),
            proof: z.string(),
          })
          .strict(),
      })
      .strict(),
  })
  .strict();

const UnsignedWitnessSchema = z
  .object({
    type: z.literal('unsigned'),
  })
  .strict();

const WitnessSchema = z.discriminatedUnion('type', [
  SimpleWitnessSchema,
  RecursiveWitnessSchema,
  UnsignedWitnessSchema,
]);

const SimpleCredentialSchema = z
  .object({
    owner: SerializedPublicKeySchema,
    data: z.record(SerializedDataValueSchema),
  })
  .strict();

const StructCredentialSchema = z
  .object({
    _type: z.literal('Struct'),
    properties: z
      .object({
        owner: SerializedPublicKeyTypeSchema,
        data: JsonSchema,
      })
      .strict(),
    value: z
      .object({
        owner: PublicKeySchema,
        data: JsonSchema,
      })
      .strict(),
  })
  .strict();

const StoredCredentialSchema = z
  .object({
    version: z.literal('v0'),
    witness: WitnessSchema,
    metadata: JsonSchema.optional(),
    credential: z.union([SimpleCredentialSchema, StructCredentialSchema]),
  })
  .strict();
