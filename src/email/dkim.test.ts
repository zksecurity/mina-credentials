import { readFile } from 'fs/promises';
import { verifyDkim } from './dkim.ts';

let email = await readFile(
  `${import.meta.dirname}/test-emails/email-good.eml`,
  'utf-8'
);
await verifyDkim(email);
