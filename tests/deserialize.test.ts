import { test } from 'node:test';
import assert from 'node:assert';
import {
  Field,
  Bool,
  UInt8,
  UInt32,
  UInt64,
  PublicKey,
  Signature,
  PrivateKey,
  DynamicProof,
  Undefined,
  Struct,
  FeatureFlags,
  Bytes,
} from 'o1js';
import { Spec, Node, Operation, Constant, Claim } from '../src/program-spec.ts';
import {
  serializeProvable,
  serializeNode,
  serializeInput,
  serializeSpec,
} from '../src/serialize-spec.ts';
import {
  deserializeSpec,
  deserializeInputs,
  deserializeInput,
  deserializeNode,
  deserializeProvableType,
  deserializeProvable,
} from '../src/deserialize-spec.ts';
import { Credential } from '../src/credential-index.ts';
import { withOwner } from '../src/credential.ts';
import {
  HttpsRequest,
  PresentationRequest,
  ZkAppRequest,
} from '../src/presentation.ts';
import { zkAppAddress } from './test-utils.ts';
import { computeContext, generateContext } from '../src/context.ts';

test('Deserialize Spec', async (t) => {
  await t.test('deserializeProvable', async (t) => {
    await t.test('Field', () => {
      const deserialized = deserializeProvable({ _type: 'Field', value: '42' });
      assert(deserialized instanceof Field, 'Should be instance of Field');
      assert.strictEqual(
        deserialized.toString(),
        '42',
        'Should have correct value'
      );
    });

    await t.test('Bool', () => {
      const deserializedTrue = deserializeProvable({
        _type: 'Bool',
        value: 'true',
      });
      assert(deserializedTrue instanceof Bool, 'Should be instance of Bool');
      assert.strictEqual(deserializedTrue.toBoolean(), true, 'Should be true');

      const deserializedFalse = deserializeProvable({
        _type: 'Bool',
        value: 'false',
      });
      assert(deserializedFalse instanceof Bool, 'Should be instance of Bool');
      assert.strictEqual(
        deserializedFalse.toBoolean(),
        false,
        'Should be false'
      );
    });

    await t.test('UInt8', () => {
      const deserialized = deserializeProvable({
        _type: 'UInt8',
        value: '255',
      });
      assert(deserialized instanceof UInt8, 'Should be instance of UInt8');
      assert.strictEqual(
        deserialized.toString(),
        '255',
        'Should have correct value'
      );
    });

    await t.test('UInt32', () => {
      const deserialized = deserializeProvable({
        _type: 'UInt32',
        value: '4294967295',
      });
      assert(deserialized instanceof UInt32, 'Should be instance of UInt32');
      assert.strictEqual(
        deserialized.toString(),
        '4294967295',
        'Should have correct value'
      );
    });

    await t.test('UInt64', () => {
      const deserialized = deserializeProvable({
        _type: 'UInt64',
        value: '18446744073709551615',
      });
      assert(deserialized instanceof UInt64, 'Should be instance of UInt64');
      assert.strictEqual(
        deserialized.toString(),
        '18446744073709551615',
        'Should have correct value'
      );
    });

    await t.test('PublicKey', () => {
      const publicKeyBase58 =
        'B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg';
      const deserialized = deserializeProvable({
        _type: 'PublicKey',
        value: publicKeyBase58,
      });
      assert(
        deserialized instanceof PublicKey,
        'Should be instance of PublicKey'
      );
      assert.strictEqual(
        deserialized.toBase58(),
        publicKeyBase58,
        'Should have correct value'
      );
    });

    await t.test('Signature', () => {
      // Create a valid signature
      const privateKey = PrivateKey.random();
      const publicKey = privateKey.toPublicKey();
      const message = [Field(1), Field(2), Field(3)];
      const signature = Signature.create(privateKey, message);

      // Serialize the signature using serializeProvable
      const serializedSignature = serializeProvable(signature);

      // Deserialize the signature
      const deserialized = deserializeProvable(serializedSignature);

      assert(
        deserialized instanceof Signature,
        'Should be instance of Signature'
      );
      assert(
        deserialized.verify(publicKey, message).toBoolean(),
        'Deserialized signature should be valid'
      );

      // Additional check to ensure serialized and deserialized signatures match
      const reserializedSignature = serializeProvable(deserialized);
      assert.deepStrictEqual(
        serializedSignature,
        reserializedSignature,
        'Serialized and reserialized signatures should match'
      );
    });

    await t.test('Invalid type', () => {
      assert.throws(
        () => deserializeProvable({ _type: 'InvalidType' as any, value: '42' }),
        { message: 'Unsupported provable type: InvalidType' },
        'Should throw for invalid type'
      );
    });
  });
});

test('deserializeProvableType', async (t) => {
  await t.test('should deserialize Field type', () => {
    const result = deserializeProvableType({ _type: 'Field' });
    assert.strictEqual(result, Field);
  });

  await t.test('should deserialize Bool type', () => {
    const result = deserializeProvableType({ _type: 'Bool' });
    assert.strictEqual(result, Bool);
  });

  await t.test('should deserialize UInt8 type', () => {
    const result = deserializeProvableType({ _type: 'UInt8' });
    assert.strictEqual(result, UInt8);
  });

  await t.test('should deserialize UInt32 type', () => {
    const result = deserializeProvableType({ _type: 'UInt32' });
    assert.strictEqual(result, UInt32);
  });

  await t.test('should deserialize UInt64 type', () => {
    const result = deserializeProvableType({ _type: 'UInt64' });
    assert.strictEqual(result, UInt64);
  });

  await t.test('should deserialize PublicKey type', () => {
    const result = deserializeProvableType({ _type: 'PublicKey' });
    assert.strictEqual(result, PublicKey);
  });

  await t.test('should deserialize Signature type', () => {
    const result = deserializeProvableType({ _type: 'Signature' });
    assert.strictEqual(result, Signature);
  });
});

test('deserializeInput', async (t) => {
  await t.test('should deserialize constant input', () => {
    const input = Constant(Field, Field(42));
    const serialized = serializeInput(input);
    const deserialized = deserializeInput(serialized);

    assert.deepStrictEqual(deserialized, input);
  });

  await t.test('should deserialize public input', () => {
    const input = Claim(Field);
    const serialized = serializeInput(input);
    const deserialized = deserializeInput(serialized);

    assert.deepStrictEqual(deserialized, input);
  });

  await t.test('should deserialize private input', () => {
    const input = Credential.Unsigned(Signature);
    const serialized = serializeInput(input);
    const deserialized = deserializeInput(serialized);

    assert.deepStrictEqual(deserialized, input);
  });

  await t.test('should deserialize credential input', () => {
    const InputData = { age: Field, isAdmin: Bool };

    const input = Credential.Simple(InputData);

    const serialized = serializeInput(input);

    const deserialized = deserializeInput(serialized);

    const reserialized = serializeInput(deserialized);

    assert.deepStrictEqual(serialized, reserialized);

    // can't compare them directly because of the verify function
    Object.entries(input).forEach(([key, value]) => {
      if (key !== 'verify') {
        assert.deepStrictEqual((deserialized as any)[key], value);
      }
    });
  });

  await t.test('should deserialize nested input', () => {
    const input = Credential.Unsigned({
      personal: {
        age: Field,
        id: UInt64,
      },
      score: UInt32,
    });
    const serialized = serializeInput(input);
    const deserialized = deserializeInput(serialized);

    assert.deepStrictEqual(deserialized, input);
  });

  await t.test('should throw error for unsupported input type', async (t) => {
    const invalidInput = { type: 'invalid' };

    try {
      deserializeInput(invalidInput);
      assert.fail('Expected an error to be thrown');
    } catch (error) {
      assert(error instanceof Error);
      assert.strictEqual(error.message, 'Invalid input type: invalid');
    }
  });
});

test('deserializeInputs', async (t) => {
  await t.test('should deserialize inputs with various type', () => {
    const inputs = {
      field: Credential.Unsigned(Field),
      bool: Claim(Bool),
      uint: Constant(UInt64, UInt64.from(42)),
      nested: Credential.Unsigned({
        inner: Field,
        deep: {
          value: Bool,
        },
      }),
    };

    const serialized = Object.fromEntries(
      Object.entries(inputs).map(([key, value]) => [key, serializeInput(value)])
    );

    const deserialized = deserializeInputs(serialized);

    assert.deepStrictEqual(deserialized, inputs);
  });

  await t.test('should deserialize credential input', () => {
    const InputData = { age: Field, isAdmin: Bool };
    const inputs = {
      credential: Credential.Simple(InputData),
    };

    const serialized = Object.fromEntries(
      Object.entries(inputs).map(([key, value]) => [key, serializeInput(value)])
    );

    const deserialized = deserializeInputs(serialized);

    const reserialized = Object.fromEntries(
      Object.entries(deserialized).map(([key, value]) => [
        key,
        serializeInput(value),
      ])
    );

    assert.deepStrictEqual(serialized, reserialized);
  });

  await t.test('should handle mixed input types', () => {
    const inputs = {
      privateField: Credential.Unsigned(Field),
      publicBool: Claim(Bool),
      constantUint: Constant(UInt32, UInt32.from(42)),
      credential: Credential.Simple({ score: UInt64 }),
    };

    const serialized = Object.fromEntries(
      Object.entries(inputs).map(([key, value]) => [key, serializeInput(value)])
    );

    const deserialized = deserializeInputs(serialized);

    const reserialized = Object.fromEntries(
      Object.entries(deserialized).map(([key, value]) => [
        key,
        serializeInput(value),
      ])
    );

    assert.deepStrictEqual(serialized, reserialized);
  });

  await t.test('should handle empty input object', () => {
    const emptyInputs = {};
    const deserialized = deserializeInputs(emptyInputs);
    assert.deepStrictEqual(deserialized, {});
  });
});

test('deserializeNode', async (t) => {
  await t.test('should deserialize constant node', () => {
    const node: Node<Field> = { type: 'constant', data: Field(123) };
    const serialized = serializeNode(node);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should deserialize root node', () => {
    let input = {
      age: Credential.Unsigned(Field),
      isAdmin: Claim(Bool),
    };
    const node: Node = { type: 'root', input };
    const serialized = serializeNode(node);
    const deserialized = deserializeNode(input, serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should deserialize property node', () => {
    let input = {
      age: Credential.Unsigned(Field),
      isAdmin: Claim(Bool),
    };
    const node: Node = {
      type: 'property',
      key: 'age',
      inner: { type: 'root', input },
    };
    const serialized = serializeNode(node);
    const deserialized = deserializeNode(input, serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should deserialize equals node', () => {
    const node: Node<Bool> = Operation.equals(
      { type: 'constant', data: Field(10) },
      { type: 'constant', data: Field(10) }
    );
    const serialized = serializeNode(node);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should deserialize lessThan node', () => {
    const node: Node<Bool> = Operation.lessThan(
      { type: 'constant', data: UInt32.from(5) },
      { type: 'constant', data: UInt32.from(10) }
    );
    const serialized = serializeNode(node);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should deserialize lessThanEq node', () => {
    const node: Node<Bool> = Operation.lessThanEq(
      { type: 'constant', data: UInt64.from(15) },
      { type: 'constant', data: UInt64.from(15) }
    );
    const serialized = serializeNode(node);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should deserialize and node', () => {
    const node: Node<Bool> = Operation.and(
      { type: 'constant', data: Bool(true) },
      { type: 'constant', data: Bool(false) }
    );
    const serialized = serializeNode(node);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should deserialize nested nodes', () => {
    const node: Node<Bool> = Operation.and(
      Operation.lessThan(
        { type: 'constant', data: Field(5) },
        { type: 'constant', data: Field(10) }
      ),
      Operation.equals(
        { type: 'constant', data: Bool(true) },
        { type: 'constant', data: Bool(true) }
      )
    );
    const serialized = serializeNode(node);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, node);
  });

  await t.test('should throw error for invalid node type', async () => {
    const invalidNode = { type: 'invalid' };

    try {
      deserializeNode({}, invalidNode);
      assert.fail('Expected an error to be thrown');
    } catch (error) {
      assert(error instanceof Error, 'Error should be an instance of Error');
      assert.strictEqual(
        error.message,
        'Invalid node type: invalid',
        'Error message should match expected message'
      );
    }
  });

  await t.test('should deserialize record node', () => {
    const originalNode: Node = Operation.record({
      field1: { type: 'constant', data: Field(123) },
      field2: { type: 'constant', data: Bool(true) },
    });
    const serialized = serializeNode(originalNode);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, originalNode);
  });

  await t.test('should deserialize add node', () => {
    const originalNode: Node<Field> = Operation.add(
      { type: 'constant', data: Field(5) },
      { type: 'constant', data: Field(10) }
    );
    const serialized = serializeNode(originalNode);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, originalNode);
  });

  await t.test('should deserialize sub node', () => {
    const originalNode: Node<Field> = Operation.sub(
      { type: 'constant', data: Field(15) },
      { type: 'constant', data: Field(7) }
    );
    const serialized = serializeNode(originalNode);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, originalNode);
  });

  await t.test('should deserialize mul node', () => {
    const originalNode: Node<UInt32> = Operation.mul(
      { type: 'constant', data: UInt32.from(3) },
      { type: 'constant', data: UInt32.from(4) }
    );
    const serialized = serializeNode(originalNode);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, originalNode);
  });

  await t.test('should deserialize div node', () => {
    const originalNode: Node<Field> = Operation.div(
      { type: 'constant', data: Field(20) },
      { type: 'constant', data: Field(5) }
    );
    const serialized = serializeNode(originalNode);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, originalNode);
  });

  await t.test('should deserialize not node', () => {
    const originalNode: Node<Bool> = Operation.not({
      type: 'constant',
      data: Bool(true),
    });
    const serialized = serializeNode(originalNode);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, originalNode);
  });

  await t.test('should deserialize hash node', () => {
    const originalNode: Node<Field> = Operation.hash({
      type: 'constant',
      data: Field(123),
    });
    const serialized = serializeNode(originalNode);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, originalNode);
  });

  await t.test('should deserialize or node', () => {
    const originalNode: Node<Bool> = Operation.or(
      { type: 'constant', data: Bool(true) },
      { type: 'constant', data: Bool(false) }
    );
    const serialized = serializeNode(originalNode);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, originalNode);
  });

  await t.test('should deserialize ifThenElse node', () => {
    const originalNode: Node<Field> = Operation.ifThenElse(
      { type: 'constant', data: Bool(true) },
      { type: 'constant', data: Field(1) },
      { type: 'constant', data: Field(0) }
    );
    const serialized = serializeNode(originalNode);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, originalNode);
  });

  await t.test('should deserialize complex nested node', () => {
    const originalNode: Node<Bool> = Operation.and(
      Operation.lessThan(
        Operation.add(
          { type: 'constant', data: Field(5) },
          { type: 'constant', data: Field(10) }
        ),
        { type: 'constant', data: Field(20) }
      ),
      Operation.or(
        { type: 'constant', data: Bool(true) },
        Operation.not({ type: 'constant', data: Bool(false) })
      )
    );
    const serialized = serializeNode(originalNode);
    const deserialized = deserializeNode({}, serialized);
    assert.deepStrictEqual(deserialized, originalNode);
  });
});

test('deserializeSpec', async (t) => {
  await t.test(
    'should correctly deserialize a simple Spec with Bytes',
    async () => {
      const originalSpec = Spec(
        {
          age: Credential.Unsigned(Field),
          isAdmin: Claim(Bool),
          maxAge: Constant(Field, Field(100)),
          name: Claim(Bytes(32)),
          constantName: Constant(Bytes(32), Bytes.fromString('hello')),
        },
        ({ age, isAdmin, maxAge }) => ({
          assert: Operation.and(Operation.lessThan(age, maxAge), isAdmin),
          ouputClaim: age,
        })
      );

      const serialized = await serializeSpec(originalSpec);
      const deserialized = await deserializeSpec(serialized);

      assert.deepStrictEqual(deserialized.inputs.age, originalSpec.inputs.age);
      assert.deepStrictEqual(
        deserialized.inputs.isAdmin,
        originalSpec.inputs.isAdmin
      );
      assert.deepEqual(
        (deserialized.inputs.name?.data as any).size,
        (originalSpec.inputs.name.data as any).size
      );
      assert.deepStrictEqual(
        deserialized.inputs.maxAge,
        originalSpec.inputs.maxAge
      );
      assert.deepStrictEqual(serialized, await serializeSpec(deserialized));
    }
  );

  // it is not possible to directly compare credentials because of the verify function
  await t.test(
    'should correctly deserialize a Spec with credential',
    async () => {
      const originalSpec = Spec(
        {
          signedData: Credential.Simple({ field: Field }),
          zeroField: Constant(Field, Field(0)),
        },
        ({ signedData, zeroField }) => ({
          assert: Operation.equals(
            Operation.property(signedData, 'field'),
            zeroField
          ),
          ouputClaim: signedData,
        })
      );

      const serialized = await serializeSpec(originalSpec);
      const deserialized = await deserializeSpec(serialized);

      const reserialized = await serializeSpec(deserialized);

      assert.deepStrictEqual(serialized, reserialized);

      assert.deepStrictEqual(
        deserialized.inputs.zeroField,
        originalSpec.inputs.zeroField
      );

      assert.deepStrictEqual(
        deserialized.inputs.signedData?.type,
        originalSpec.inputs.signedData.type
      );

      assert.deepStrictEqual(
        deserialized.inputs.signedData.witness,
        originalSpec.inputs.signedData.witness
      );
      assert.deepStrictEqual(
        deserialized.inputs.signedData.data,
        originalSpec.inputs.signedData.data
      );
    }
  );

  await t.test(
    'should correctly deserialize a Spec with nested operations',
    async () => {
      const originalSpec = Spec(
        {
          field1: Credential.Unsigned(Field),
          field2: Credential.Unsigned(Field),
          threshold: Claim(UInt64),
        },
        ({ field1, field2, threshold }) => ({
          assert: Operation.and(
            Operation.lessThan(field1, field2),
            Operation.lessThanEq(field2, threshold)
          ),
          ouputClaim: Operation.equals(field1, field2),
        })
      );

      const serialized = await serializeSpec(originalSpec);
      const deserialized = await deserializeSpec(serialized);

      const reserialized = await serializeSpec(deserialized);

      assert.deepStrictEqual(serialized, reserialized);

      assert.deepStrictEqual(deserialized.inputs, originalSpec.inputs);
      assert.deepStrictEqual(deserialized.logic, originalSpec.logic);
    }
  );

  await t.test(
    'should correctly deserialize a spec with owner and issuer',
    async (t) => {
      const InputData = { age: Field };
      const SignedData = Credential.Simple(InputData);

      const originalSpec = Spec(
        {
          signedData: SignedData,
          targetAge: Claim(Field),
        },
        ({ signedData, targetAge }) => ({
          assert: Operation.equals(
            Operation.property(signedData, 'age'),
            targetAge
          ),
          ouputClaim: Operation.record({
            owner: Operation.owner,
            issuer: Operation.issuer(signedData),
            age: Operation.property(signedData, 'age'),
          }),
        })
      );

      const originalSerialized = await serializeSpec(originalSpec);
      const deserialized = await deserializeSpec(originalSerialized);
      const reSerialized = await serializeSpec(deserialized);

      assert.strictEqual(originalSerialized, reSerialized);
    }
  );

  await t.test(
    'should correctly deserialize a Spec with recursive credential',
    async () => {
      class RecursiveProof extends DynamicProof<undefined, Credential<Field>> {
        static publicInputType = Undefined;
        static publicOutputType = Struct(withOwner(Field));
        static maxProofsVerified: 0 = 0;
        static featureFlags = FeatureFlags.allMaybe;
      }

      const originalSpec = Spec(
        {
          provedData: Credential.Recursive(RecursiveProof, Field),
          zeroField: Constant(Field, Field(0)),
        },
        ({ provedData, zeroField }) => ({
          assert: Operation.equals(provedData, zeroField),
          ouputClaim: provedData,
        })
      );

      const serialized = await serializeSpec(originalSpec);
      const deserialized = await deserializeSpec(serialized);

      const reserialized = await serializeSpec(deserialized);

      assert.deepStrictEqual(serialized, reserialized);

      assert.deepStrictEqual(
        deserialized.inputs.zeroField,
        originalSpec.inputs.zeroField
      );

      assert.deepStrictEqual(
        deserialized.inputs.provedData?.type,
        originalSpec.inputs.provedData.type
      );
      assert.deepStrictEqual(
        deserialized.inputs.provedData.data,
        originalSpec.inputs.provedData.data
      );

      let DeserializedProof: typeof DynamicProof = (
        originalSpec.inputs.provedData.witness as any
      ).proof;
      assert.deepStrictEqual(
        DeserializedProof.featureFlags,
        RecursiveProof.featureFlags
      );
      assert.deepStrictEqual(
        DeserializedProof.maxProofsVerified,
        RecursiveProof.maxProofsVerified
      );
    }
  );
});

test('deserializePresentationRequest with context', async (t) => {
  const Bytes32 = Bytes(32);
  const InputData = { age: Field, name: Bytes32 };

  const spec = Spec(
    {
      signedData: Credential.Simple(InputData),
      targetAge: Claim(Field),
      targetName: Constant(Bytes32, Bytes32.fromString('Alice')),
    },
    ({ signedData, targetAge, targetName }) => ({
      assert: Operation.and(
        Operation.equals(Operation.property(signedData, 'age'), targetAge),
        Operation.equals(Operation.property(signedData, 'name'), targetName)
      ),
      ouputClaim: Operation.property(signedData, 'age'),
    })
  );

  await t.test('should deserialize zk-app context correctly', () => {
    const originalRequest = ZkAppRequest({
      spec,
      claims: { targetAge: Field(18) },
      inputContext: {
        type: 'zk-app',
        vkHash: Field(123),
        action: Field(123), // Mock method ID + args hash
        claims: Field(456),
        serverNonce: Field(789),
      },
    });

    const serialized = PresentationRequest.toJSON(originalRequest);
    const deserialized = PresentationRequest.fromJSON<typeof originalRequest>(
      'zk-app',
      serialized
    );

    assert.strictEqual(deserialized.type, 'zk-app');
    assert.strictEqual(deserialized.claims.targetAge.toString(), '18');

    const reserialized = PresentationRequest.toJSON(deserialized);
    assert.deepStrictEqual(reserialized, serialized);

    const context = deserialized.inputContext;
    assert(context, 'Context should exist');
    assert.deepStrictEqual(context.vkHash, Field(123));
    assert.deepStrictEqual(context.action, Field(123));
    assert.deepStrictEqual(context.serverNonce, Field(789));

    const walletContext = {
      verifierIdentity: zkAppAddress,
      clientNonce: Field(999),
    };

    const originalContext = generateContext(
      computeContext({
        ...originalRequest.inputContext,
        ...walletContext,
      })
    );
    const deserializedContext = generateContext(
      computeContext({
        ...deserialized.inputContext,
        ...walletContext,
      })
    );
    assert.deepStrictEqual(deserializedContext, originalContext);
  });

  await t.test('should deserialize https context correctly', async () => {
    const serverUrl = 'test.com';

    const originalRequest = HttpsRequest({
      spec,
      claims: { targetAge: Field(18) },
      inputContext: {
        type: 'https',
        vkHash: Field(123),
        action: 'POST /api/verify',
        claims: Field(456),
        serverNonce: Field(789),
      },
    });

    const serialized = PresentationRequest.toJSON(originalRequest);
    const deserialized = PresentationRequest.fromJSON<typeof originalRequest>(
      'https',
      serialized
    );

    assert.strictEqual(deserialized.type, 'https');
    assert.strictEqual(deserialized.claims.targetAge.toString(), '18');

    const reserialized = PresentationRequest.toJSON(deserialized);
    assert.deepStrictEqual(reserialized, serialized);

    const context = deserialized.inputContext;
    assert(context, 'Context should exist');
    assert.deepStrictEqual(context.vkHash, Field(123));
    assert.strictEqual(context.action, 'POST /api/verify');
    assert.deepStrictEqual(context.serverNonce, Field(789));

    const walletContext = {
      verifierIdentity: serverUrl,
      clientNonce: Field(999),
    };

    const originalContext = generateContext(
      computeContext({
        ...originalRequest.inputContext,
        ...walletContext,
      })
    );
    const deserializedContext = generateContext(
      computeContext({
        ...deserialized.inputContext,
        ...walletContext,
      })
    );
    assert.deepStrictEqual(deserializedContext, originalContext);
  });
});
