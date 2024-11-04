import { test } from 'node:test';
import assert from 'node:assert';
import { Credential } from '../src/credential-index.ts';
import {
  StoredCredentialSchema,
  NodeSchema,
  InputSchema,
  ContextSchema,
  PresentationRequestSchema,
} from '../src/validation.ts';
import {
  Bool,
  Bytes,
  Field,
  PrivateKey,
  PublicKey,
  Signature,
  UInt32,
  UInt64,
} from 'o1js';
import { owner, issuerKey } from './test-utils.ts';
import { Spec, Claim, Operation, Node, Constant } from '../src/program-spec.ts';
import { createProgram } from '../src/program.ts';
import { createUnsigned } from '../src/credential.ts';
import {
  serializeInput,
  serializeInputContext,
  serializeNode,
} from '../src/serialize.ts';
import { PresentationRequest } from '../src/index.ts';

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
        outputClaim: Operation.record({ owner: inputOwner, data }),
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

test('NodeSchema validation', async (t) => {
  await t.test('should validate equalsOneOf Node with array options', () => {
    const options: Node<Field>[] = [
      { type: 'constant', data: Field(10) },
      { type: 'constant', data: Field(20) },
      { type: 'constant', data: Field(30) },
    ];

    const equalsOneOfNode: Node<Bool> = Operation.equalsOneOf(
      { type: 'constant', data: Field(20) },
      options
    );

    const serialized = serializeNode(equalsOneOfNode);

    const result = NodeSchema.safeParse(serialized);

    assert(
      result.success,
      'Node should be valid with array options: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });

  await t.test(
    'should validate equalsOneOf Node with single node options',
    () => {
      const optionsNode: Node<Field[]> = {
        type: 'constant',
        data: [Field(10), Field(20), Field(30)],
      };

      const equalsOneOfNode: Node<Bool> = Operation.equalsOneOf(
        { type: 'constant', data: Field(20) },
        optionsNode
      );

      const serialized = serializeNode(equalsOneOfNode);

      const result = NodeSchema.safeParse(serialized);

      assert(
        result.success,
        'Node should be valid with single node options: ' +
          (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
      );
    }
  );
});

test('InputSchema validation', async (t) => {
  await t.test('validates simple credential input', () => {
    const input = Credential.Simple({
      age: Field,
      verified: Bool,
    });

    const serialized = serializeInput(input);

    const result = InputSchema.safeParse(serialized);

    assert(
      result.success,
      'Simple credential input should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });

  await t.test('validates claim input', () => {
    const input = Claim(UInt64);

    const serialized = serializeInput(input);

    const result = InputSchema.safeParse(serialized);

    assert(
      result.success,
      'Claim input should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });

  await t.test('validates constant input', () => {
    const input = Constant(Signature, Signature.empty());

    const serialized = serializeInput(input);

    const result = InputSchema.safeParse(serialized);

    assert(
      result.success,
      'Constant input should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });

  await t.test('validates input with nested structure', () => {
    const input = Credential.Simple({
      personal: {
        age: Field,
        score: UInt64,
      },
      verified: Bool,
    });

    const serialized = serializeInput(input);

    const result = InputSchema.safeParse(serialized);

    assert(
      result.success,
      'Nested structure input should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });
});

test('ContextSchema validation', async (t) => {
  await t.test('validates HTTPS context', () => {
    const httpsContext = {
      type: 'https' as const,
      action: 'POST /api/verify',
      serverNonce: Field(123456789),
    };

    const serialized = serializeInputContext(httpsContext);
    const result = ContextSchema.safeParse(serialized);
    assert(
      result.success,
      'Valid HTTPS context should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });

  await t.test('validates ZkApp context', () => {
    const actualContext = {
      type: 'zk-app' as const,
      action: Field(123456789),
      serverNonce: Field(987654321),
    };

    const serialized = serializeInputContext(actualContext);
    const result = ContextSchema.safeParse(serialized);
    assert(
      result.success,
      'Valid ZkApp context should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });
});

test('PresentationRequestSchema validation', async (t) => {
  const spec = Spec(
    {
      signedData: Credential.Simple({ age: Field, name: Bytes32 }),
      targetAge: Claim(Field),
      targetName: Constant(Bytes32, Bytes32.fromString('Alice')),
    },
    ({ signedData, targetAge, targetName }) => ({
      assert: Operation.and(
        Operation.equals(Operation.property(signedData, 'age'), targetAge),
        Operation.equals(Operation.property(signedData, 'name'), targetName)
      ),
      outputClaim: Operation.property(signedData, 'age'),
    })
  );

  await t.test('validates no-context presentation request', () => {
    let requestInitial = PresentationRequest.noContext(spec, {
      targetAge: Field(18),
    });
    let serialized = JSON.parse(PresentationRequest.toJSON(requestInitial));

    const result = PresentationRequestSchema.safeParse(serialized);
    assert(
      result.success,
      'No-context presentation request should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });

  await t.test('validates zk-app presentation request', () => {
    const request = PresentationRequest.zkApp(
      spec,
      {
        targetAge: Field(18),
      },
      {
        action: Field(123), // Mock method ID + args hash
      }
    );

    const serialized = JSON.parse(PresentationRequest.toJSON(request));

    const result = PresentationRequestSchema.safeParse(serialized);
    assert(
      result.success,
      'ZkApp presentation request should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });

  await t.test('validates https presentation request', () => {
    const request = PresentationRequest.https(
      spec,
      {
        targetAge: Field(18),
      },
      {
        action: 'POST /api/verify',
      }
    );

    const serialized = JSON.parse(PresentationRequest.toJSON(request));

    const result = PresentationRequestSchema.safeParse(serialized);
    assert(
      result.success,
      'HTTPS presentation request should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });

  await t.test('validates complex presentation request', () => {
    const InputData = { age: Field, name: Bytes32 };
    const NestedInputData = { person: InputData, points: Field };

    const spec = Spec(
      {
        data: Credential.Simple(NestedInputData),
        targetAge: Claim(Field),
        targetPoints: Claim(Field),
      },
      ({ data, targetAge, targetPoints }) => ({
        assert: Operation.and(
          Operation.equals(
            Operation.property(Operation.property(data, 'person'), 'age'),
            targetAge
          ),
          Operation.equals(Operation.property(data, 'points'), targetPoints)
        ),
        outputClaim: Operation.property(
          Operation.property(data, 'person'),
          'name'
        ),
      })
    );

    const request = PresentationRequest.zkApp(
      spec,
      { targetAge: Field(25), targetPoints: Field(100) },
      { action: Field(123) }
    );

    const serialized = JSON.parse(PresentationRequest.toJSON(request));

    const result = PresentationRequestSchema.safeParse(serialized);
    assert(
      result.success,
      'HTTPS presentation request should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });
});
