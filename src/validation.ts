import { z } from 'zod';

export { StoredCredentialSchema };

// Literal, Json, LiteralSchema and JsonSchema were copied from
// https://github.com/palladians/mina-js/tree/main

type Literal = string | number | boolean | null;
type Json = Literal | { [key: string]: Json } | Json[];

const LiteralSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]);

const JsonSchema: z.ZodType<Json> = z.lazy(() =>
  z.union([LiteralSchema, z.array(JsonSchema), z.record(JsonSchema)])
);

const PublicKeySchema = z.string().length(55).startsWith('B62');

const SerializedValueSchema = z
  .object({
    _type: z.string(),
    value: z.union([z.string(), z.record(z.any())]),
  })
  .strict();

const SerializedTypeSchema = z
  .object({
    _type: z.string(),
  })
  .strict();

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
    data: z.record(SerializedValueSchema),
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

// we could infer the type of StoredCredential from the validation
// type StoredCredential = z.infer<typeof StoredCredentialSchema>;
