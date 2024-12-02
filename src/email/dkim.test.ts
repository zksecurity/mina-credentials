import fs from 'fs';
import path from 'path';
import { verifyDKIMSignature } from './dkim/index.ts';
import { it } from 'node:test';
import assert from 'assert';

it('should pass for valid email', async () => {
  const email = fs.readFileSync(
    path.resolve(import.meta.dirname, './email-good.eml')
  );

  const result = await verifyDKIMSignature(email);

  assert.strictEqual(result.signingDomain, 'icloud.com');
  assert(!result.appliedSanitization);
});
