import { z } from 'zod';

export {
  StoredCredentialSchema,
  PresentationRequestSchema,
  NodeSchema,
  InputSchema,
  ContextSchema,
};

type Literal = string | number | boolean | null;
type Json = Literal | { [key: string]: Json } | Json[];

const LiteralSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]);

const JsonSchema: z.ZodType<Json> = z.lazy(() =>
  z.union([LiteralSchema, z.array(JsonSchema), z.record(JsonSchema)])
);

const PublicKeySchema = z.string().length(55).startsWith('B62');

interface SerializedValue {
  _type: string;
  value: Json;
  properties?: Record<string, unknown>;
}

interface ProofType {
  name: string;
  publicInput: SerializedType;
  publicOutput: SerializedType;
  maxProofsVerified: number;
  featureFlags: Record<string, unknown>;
}

interface DynamicString {
  _type: 'DynamicString';
  _isFactory: true;
  maxLength: number;
  value?: string;
}

interface DynamicArray {
  _type: 'DynamicArray';
  _isFactory: true;
  maxLength: number;
  innerType: SerializedType;
  value?: SerializedValue[];
}

interface DynamicRecord {
  _type: 'DynamicRecord';
  _isFactory: true;
  maxEntries: number;
  knownShape: Record<string, SerializedType>;
  value?: Record<string, SerializedValue>;
}

interface DynamicBytes {
  _type: 'DynamicBytes';
  _isFactory: true;
  maxLength: number;
  value?: string; // hex string
}

interface BasicType {
  _type: string;
}

// TODO: type?
interface ConstantType {
  type: 'Constant';
  value: string;
}

interface BytesType {
  _type: 'Bytes';
  size: number;
}

interface ProofTypeWrapper {
  _type: 'Proof';
  proof: ProofType;
}

interface ArrayType {
  _type: 'Array';
  innerType: SerializedType;
  size: number;
}

interface StructType {
  _type: 'Struct';
  properties: { [key: string]: SerializedType };
}

type SerializedType =
  | BasicType
  | ConstantType
  | BytesType
  | ProofTypeWrapper
  | ArrayType
  | StructType
  | DynamicString
  | DynamicArray
  | DynamicRecord
  | DynamicBytes
  | { [key: string]: SerializedType };

// Base schemas for values
const SerializedValueSchema = z
  .object({
    _type: z.string(),
    value: JsonSchema,
    properties: z.record(z.any()).optional(),
  })
  .strict();

const SerializedDataValueSchema = z.union([
  SerializedValueSchema,
  z.string(),
  z.number(),
  z.boolean(),
]);

const FactorySchema = z
  .object({
    _isFactory: z.literal(true),
  })
  .strict();

// Dynamic type schemas
const DynamicTypeBaseSchema = z.object({
  _type: z.string(),
  _isFactory: z.literal(true),
});

const DynamicStringSchema = DynamicTypeBaseSchema.extend({
  _type: z.literal('DynamicString'),
  maxLength: z.number(),
  value: z.string().optional(),
}).strict();

const DynamicArraySchema = DynamicTypeBaseSchema.extend({
  _type: z.literal('DynamicArray'),
  maxLength: z.number(),
  innerType: z.lazy(() => SerializedTypeSchema),
  value: z.array(SerializedValueSchema).optional(),
}).strict();

const DynamicRecordSchema = DynamicTypeBaseSchema.extend({
  _type: z.literal('DynamicRecord'),
  maxEntries: z.number(),
  knownShape: z.record(z.lazy(() => SerializedTypeSchema)),
  value: z.record(SerializedValueSchema).optional(),
}).strict();

const DynamicBytesSchema = DynamicTypeBaseSchema.extend({
  _type: z.literal('DynamicBytes'),
  maxLength: z.number(),
  value: z.string().optional(), // hex string
}).strict();

const ProofTypeSchema: z.ZodType<ProofType> = z.lazy(() =>
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
    z
      .object({
        _type: z.string(),
      })
      .strict(),
    // Constant type
    z
      .object({
        type: z.literal('Constant'),
        value: z.string(),
      })
      .strict(),
    // Bytes type
    z
      .object({
        _type: z.literal('Bytes'),
        size: z.number(),
      })
      .strict(),
    // Proof type
    z
      .object({
        _type: z.literal('Proof'),
        proof: ProofTypeSchema,
      })
      .strict(),
    // Array type
    z
      .object({
        _type: z.literal('Array'),
        innerType: SerializedTypeSchema,
        size: z.number(),
      })
      .strict(),
    // Struct type
    z
      .object({
        _type: z.literal('Struct'),
        properties: z.record(SerializedTypeSchema),
      })
      .strict(),
    // Dynamic types
    DynamicStringSchema,
    DynamicArraySchema,
    DynamicRecordSchema,
    DynamicBytesSchema,
    // Allow records of nested types for Struct
    z.record(SerializedTypeSchema),
  ])
);

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
      witness: z.union([z.record(SerializedTypeSchema), SerializedTypeSchema]),
      data: z.union([z.record(SerializedTypeSchema), SerializedTypeSchema]),
    })
    .strict(),

  z
    .object({
      type: z.literal('constant'),
      data: SerializedTypeSchema,
      value: z.union([z.string(), z.record(z.string())]),
    })
    .strict(),

  z
    .object({
      type: z.literal('claim'),
      data: z.union([z.record(SerializedTypeSchema), SerializedTypeSchema]),
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
    claims: z.record(
      z.union([
        SerializedValueSchema,
        DynamicStringSchema,
        DynamicArraySchema,
        DynamicRecordSchema,
        DynamicBytesSchema,
      ])
    ),
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
