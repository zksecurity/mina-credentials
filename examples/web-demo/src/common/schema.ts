import { Bytes } from 'o1js';
import { Schema } from '../../../..';
import { z } from 'zod';

export { type DataInput, type Data, dataFromInput, ZodSchemas };

type DataInput = {
  name: string;
  birthDate: number;
  nationality: string;
  id: string;
  expiresAt: number;
};
type Data = ReturnType<typeof schema.from>;

const Bytes16 = Bytes(16);

const schema = Schema({
  /**
   * Nationality of the owner.
   */
  nationality: Schema.String,

  /**
   * Full name of the owner.
   */
  name: Schema.String,

  /**
   * Date of birth of the owner.
   */
  birthDate: Schema.Number,

  /**
   * Owner ID (16 bytes).
   */
  id: Bytes16,

  /**
   * Timestamp when the credential expires.
   */
  expiresAt: Schema.Number,
});

function dataFromInput(input: DataInput): Data {
  let id = Bytes16.fromHex(input.id);
  return schema.from({ ...input, id });
}

// zod validation

const PublicKey = z.object({
  _type: z.literal('PublicKey'),
  value: z.string(),
});

const Data = z.object({
  name: z.string(),
  nationality: z.string(),
  birthDate: z.object({ _type: z.literal('UInt64'), value: z.string() }),
  id: z.object({
    _type: z.literal('Bytes'),
    size: z.literal(16),
    value: z.string(),
  }),
  expiresAt: z.object({ _type: z.literal('UInt64'), value: z.string() }),
});

const CredentialData = z.object({ owner: PublicKey, data: Data }).strict();

const ZodSchemas = { PublicKey, Data, CredentialData };
