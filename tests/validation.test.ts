import { test } from 'node:test';
import assert from 'node:assert';
import { Credential } from '../src/credential-index.ts';
import { StoredCredentialSchema } from '../src/validation.ts';
import { Bytes, Field, PublicKey, Signature } from 'o1js';
import { owner, issuerKey } from './test-utils.ts';
import { Spec, Claim, Operation } from '../src/program-spec.ts';
import { createProgram } from '../src/program.ts';
import { createUnsigned } from '../src/credential.ts';

const Bytes32 = Bytes(32);

test('StoredCredentialSchema validation', async (t) => {
  await t.test('validates simple credential', () => {
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

  await t.test('validates recursive credential', async () => {
    const InputData = { age: Field, name: Bytes32 };
    const inputProofSpec = Spec(
      { inputOwner: Claim(PublicKey), data: Claim(InputData) },
      ({ inputOwner, data }) => ({
        ouputClaim: Operation.record({ owner: inputOwner, data }),
      })
    );

    // create recursive credential
    const Recursive = await Credential.Recursive.fromProgram(
      createProgram(inputProofSpec)
    );
    let data = { age: Field(18), name: Bytes32.fromString('Alice') };
    let provedData = await Recursive.create({
      claims: { inputOwner: owner, data },
      credentials: {},
      context: Field(0), // dummy context
      ownerSignature: Signature.empty(), // no credential => no signature verification
    });

    const serialized = Credential.toJSON(provedData);
    const parsed = JSON.parse(serialized);

    const result = StoredCredentialSchema.safeParse(parsed);
    assert(
      result.success,
      'Recursive credential JSON should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });

  await t.test('should validate a valid unsigned credential', () => {
    const unsignedCredential = createUnsigned({
      age: Field(42),
      name: Bytes32.fromString('Alice'),
    });

    const serialized = Credential.toJSON(unsignedCredential);
    const parsed = JSON.parse(serialized);

    const result = StoredCredentialSchema.safeParse(parsed);
    assert(
      result.success,
      'Unsigned credential JSON should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });
});
