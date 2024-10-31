import { test } from 'node:test';
import assert from 'node:assert';
import { Credential } from '../src/credential-index.ts';
import { StoredCredentialSchema } from '../src/validation.ts';
import { Field } from 'o1js';
import { owner, issuerKey } from './test-utils.ts';

test('StoredCredentialSchema validation', async (t) => {
  await t.test('validates simple credential after toJSON', () => {
    const data = { age: Field(25) };
    const signedCredential = Credential.sign(issuerKey, { owner, data });
    const serialized = Credential.toJSON(signedCredential);
    const parsed = JSON.parse(serialized);

    const result = StoredCredentialSchema.safeParse(parsed);
    assert(
      result.success,
      'Simple credential JSON should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });
});
