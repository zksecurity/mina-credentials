import { test } from 'node:test';
import assert from 'node:assert';
import { Operation, Spec, Node, Claim, Constant } from '../src/program-spec.ts';
import {
  serializeProvableType,
  serializeNestedProvable,
  serializeNode,
  serializeInput,
  convertSpecToSerializable,
  serializeSpec,
  validateSpecHash,
} from '../src/serialize-spec.ts';
import { Bool, Field, PublicKey, Signature, UInt32, UInt64, UInt8 } from 'o1js';
import { deserializeSpec } from '../src/deserialize-spec.ts';
import { Credential } from '../src/credential-index.ts';

test('Serialize Inputs', async (t) => {
  await t.test('should serialize basic types correctly', () => {
    assert.deepStrictEqual(serializeProvableType(Field), { _type: 'Field' });
    assert.deepStrictEqual(serializeProvableType(Bool), { _type: 'Bool' });
    assert.deepStrictEqual(serializeProvableType(UInt8), { _type: 'UInt8' });
    assert.deepStrictEqual(serializeProvableType(UInt32), { _type: 'UInt32' });
    assert.deepStrictEqual(serializeProvableType(UInt64), { _type: 'UInt64' });
    assert.deepStrictEqual(serializeProvableType(PublicKey), {
      _type: 'PublicKey',
    });
    assert.deepStrictEqual(serializeProvableType(Signature), {
      _type: 'Signature',
    });
  });

  await t.test('should serialize structs correctly', () => {
    // TODO: implement
  });

  await t.test('should serialize simple provable types (nested)', () => {
    assert.deepStrictEqual(serializeNestedProvable(Field), {
      _type: 'Field',
    });
    assert.deepStrictEqual(serializeNestedProvable(Bool), { _type: 'Bool' });
    assert.deepStrictEqual(serializeNestedProvable(UInt8), { _type: 'UInt8' });
    assert.deepStrictEqual(serializeNestedProvable(UInt32), {
      _type: 'UInt32',
    });
    assert.deepStrictEqual(serializeNestedProvable(UInt64), {
      _type: 'UInt64',
    });
    assert.deepStrictEqual(serializeNestedProvable(PublicKey), {
      _type: 'PublicKey',
    });
    assert.deepStrictEqual(serializeNestedProvable(Signature), {
      _type: 'Signature',
    });
  });

  await t.test('should serialize nested objects with provable types', () => {
    const nestedType = {
      field: Field,
      nested: {
        uint: UInt32,
        bool: Bool,
      },
    };

    assert.deepStrictEqual(serializeNestedProvable(nestedType), {
      field: { _type: 'Field' },
      nested: {
        bool: { _type: 'Bool' },
        uint: { _type: 'UInt32' },
      },
    });
  });

  await t.test('should serialize complex nested structures', () => {
    const complexType = {
      simpleField: Field,
      nestedObject: {
        publicKey: PublicKey,
        signature: Signature,
        deeplyNested: {
          bool: Bool,
          uint64: UInt64,
        },
      },
    };

    assert.deepStrictEqual(serializeNestedProvable(complexType), {
      simpleField: { _type: 'Field' },
      nestedObject: {
        publicKey: { _type: 'PublicKey' },
        signature: { _type: 'Signature' },
        deeplyNested: {
          bool: { _type: 'Bool' },
          uint64: { _type: 'UInt64' },
        },
      },
    });
  });

  await t.test('should throw an error for unsupported types', () => {
    assert.throws(() => serializeNestedProvable(123 as any), {
      name: 'Error',
      message: 'Unsupported type in NestedProvable: 123',
    });
  });
});

test('Serialize Nodes', async (t) => {
  await t.test('should serialize constant Node', () => {
    const constantNode: Node<Field> = { type: 'constant', data: Field(123) };

    const serialized = serializeNode(constantNode);

    const expected = {
      type: 'constant',
      data: { _type: 'Field', value: '123' },
    };

    assert.deepEqual(serialized, expected);
  });

  await t.test('should serialize root Node', () => {
    const rootNode: Node = {
      type: 'root',
      input: {
        age: Credential.Unsigned(Field),
        isAdmin: Claim(Bool),
      },
    };

    const serialized = serializeNode(rootNode);

    const expected = { type: 'root' };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize property Node', () => {
    const propertyNode: Node = {
      type: 'property',
      key: 'age',
      inner: {
        type: 'root',
        input: {
          age: Credential.Unsigned(Field),
          isAdmin: Claim(Bool),
        },
      },
    };

    const serialized = serializeNode(propertyNode);

    const expected = { type: 'property', key: 'age', inner: { type: 'root' } };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize equals Node', () => {
    const equalsNode: Node<Bool> = Operation.equals(
      { type: 'constant', data: Field(10) },
      { type: 'constant', data: Field(10) }
    );

    const serialized = serializeNode(equalsNode);

    const expected = {
      type: 'equals',
      left: { type: 'constant', data: { _type: 'Field', value: '10' } },
      right: { type: 'constant', data: { _type: 'Field', value: '10' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize lessThan Node', () => {
    const lessThanNode: Node<Bool> = Operation.lessThan(
      { type: 'constant', data: UInt32.from(5) },
      { type: 'constant', data: UInt32.from(10) }
    );

    const serialized = serializeNode(lessThanNode);

    const expected = {
      type: 'lessThan',
      left: { type: 'constant', data: { _type: 'UInt32', value: '5' } },
      right: { type: 'constant', data: { _type: 'UInt32', value: '10' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize lessThanEq Node', () => {
    const lessThanEqNode: Node<Bool> = Operation.lessThanEq(
      { type: 'constant', data: UInt64.from(15) },
      { type: 'constant', data: UInt64.from(15) }
    );

    const serialized = serializeNode(lessThanEqNode);

    const expected = {
      type: 'lessThanEq',
      left: { type: 'constant', data: { _type: 'UInt64', value: '15' } },
      right: { type: 'constant', data: { _type: 'UInt64', value: '15' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize and Node', () => {
    const andNode: Node<Bool> = Operation.and(
      { type: 'constant', data: Bool(true) },
      { type: 'constant', data: Bool(false) }
    );

    const serialized = serializeNode(andNode);

    const expected = {
      type: 'and',
      left: { type: 'constant', data: { _type: 'Bool', value: 'true' } },
      right: { type: 'constant', data: { _type: 'Bool', value: 'false' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize or Node', () => {
    const orNode: Node<Bool> = Operation.or(
      { type: 'constant', data: Bool(true) },
      { type: 'constant', data: Bool(false) }
    );

    const serialized = serializeNode(orNode);

    const expected = {
      type: 'or',
      left: { type: 'constant', data: { _type: 'Bool', value: 'true' } },
      right: { type: 'constant', data: { _type: 'Bool', value: 'false' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize add Node', () => {
    const addNode: Node<Field> = Operation.add(
      { type: 'constant', data: Field(5) },
      { type: 'constant', data: Field(10) }
    );

    const serialized = serializeNode(addNode);

    const expected = {
      type: 'add',
      left: { type: 'constant', data: { _type: 'Field', value: '5' } },
      right: { type: 'constant', data: { _type: 'Field', value: '10' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize sub Node', () => {
    const subNode: Node<Field> = Operation.sub(
      { type: 'constant', data: Field(15) },
      { type: 'constant', data: Field(7) }
    );

    const serialized = serializeNode(subNode);

    const expected = {
      type: 'sub',
      left: { type: 'constant', data: { _type: 'Field', value: '15' } },
      right: { type: 'constant', data: { _type: 'Field', value: '7' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize mul Node', () => {
    const mulNode: Node<Field> = Operation.mul(
      { type: 'constant', data: Field(3) },
      { type: 'constant', data: Field(4) }
    );

    const serialized = serializeNode(mulNode);

    const expected = {
      type: 'mul',
      left: { type: 'constant', data: { _type: 'Field', value: '3' } },
      right: { type: 'constant', data: { _type: 'Field', value: '4' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize div Node', () => {
    const divNode: Node<Field> = Operation.div(
      { type: 'constant', data: Field(20) },
      { type: 'constant', data: Field(5) }
    );

    const serialized = serializeNode(divNode);

    const expected = {
      type: 'div',
      left: { type: 'constant', data: { _type: 'Field', value: '20' } },
      right: { type: 'constant', data: { _type: 'Field', value: '5' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize not Node', () => {
    const notNode: Node<Bool> = Operation.not({
      type: 'constant',
      data: Bool(true),
    });

    const serialized = serializeNode(notNode);

    const expected = {
      type: 'not',
      inner: { type: 'constant', data: { _type: 'Bool', value: 'true' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize hash Node', () => {
    const hashNode: Node<Field> = Operation.hash({
      type: 'constant',
      data: Field(123),
    });

    const serialized = serializeNode(hashNode);

    const expected = {
      type: 'hash',
      inner: { type: 'constant', data: { _type: 'Field', value: '123' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize ifThenElse Node', () => {
    const ifThenElseNode: Node<Field> = Operation.ifThenElse(
      { type: 'constant', data: Bool(true) },
      { type: 'constant', data: Field(1) },
      { type: 'constant', data: Field(0) }
    );

    const serialized = serializeNode(ifThenElseNode);

    const expected = {
      type: 'ifThenElse',
      condition: { type: 'constant', data: { _type: 'Bool', value: 'true' } },
      thenNode: { type: 'constant', data: { _type: 'Field', value: '1' } },
      elseNode: { type: 'constant', data: { _type: 'Field', value: '0' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize record Node', () => {
    const recordNode: Node = Operation.record({
      field1: { type: 'constant', data: Field(123) },
      field2: { type: 'constant', data: Bool(true) },
    });

    const serialized = serializeNode(recordNode);

    const expected = {
      type: 'record',
      data: {
        field1: { type: 'constant', data: { _type: 'Field', value: '123' } },
        field2: { type: 'constant', data: { _type: 'Bool', value: 'true' } },
      },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize nested Nodes', () => {
    const nestedNode: Node<Bool> = Operation.and(
      Operation.lessThan(
        { type: 'constant', data: Field(5) },
        { type: 'constant', data: Field(10) }
      ),
      Operation.equals(
        { type: 'constant', data: Bool(true) },
        { type: 'constant', data: Bool(true) }
      )
    );

    const serialized = serializeNode(nestedNode);

    const expected = {
      type: 'and',
      left: {
        type: 'lessThan',
        left: { type: 'constant', data: { _type: 'Field', value: '5' } },
        right: { type: 'constant', data: { _type: 'Field', value: '10' } },
      },
      right: {
        type: 'equals',
        left: { type: 'constant', data: { _type: 'Bool', value: 'true' } },
        right: { type: 'constant', data: { _type: 'Bool', value: 'true' } },
      },
    };

    assert.deepStrictEqual(serialized, expected);
  });
});

test('serializeInput', async (t) => {
  await t.test('should serialize constant input', () => {
    const input = Constant(Field, Field(42));

    const serialized = serializeInput(input);

    const expected = {
      type: 'constant',
      data: { _type: 'Field' },
      value: '42',
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize public input', () => {
    const input = Claim(Field);

    const serialized = serializeInput(input);

    const expected = {
      type: 'public',
      data: { _type: 'Field' },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize private input', () => {
    const input = Credential.Unsigned(Field);

    const serialized = serializeInput(input);

    const expected = {
      type: 'credential',
      id: 'none',
      witness: { _type: 'Undefined' },
      data: { _type: 'Field' },
    };
    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize credential input', () => {
    const InputData = { age: Field, isAdmin: Bool };
    const input = Credential.Simple(InputData);

    const serialized = serializeInput(input);

    const expected = {
      type: 'credential',
      id: 'signature-native',
      witness: {
        type: { type: 'Constant', value: 'simple' },
        issuer: { _type: 'PublicKey' },
        issuerSignature: { _type: 'Signature' },
      },
      data: {
        age: { _type: 'Field' },
        isAdmin: { _type: 'Bool' },
      },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize nested input', () => {
    const NestedInputData = {
      personal: {
        age: Field,
        id: UInt64,
      },
      score: UInt32,
    };
    const input = Credential.Unsigned(NestedInputData);

    const serialized = serializeInput(input);

    const expected = {
      type: 'credential',
      id: 'none',
      witness: { _type: 'Undefined' },
      data: {
        personal: {
          age: { _type: 'Field' },
          id: { _type: 'UInt64' },
        },
        score: { _type: 'UInt32' },
      },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should throw error for unsupported input type', () => {
    const invalidInput = { type: 'invalid' } as any;
    assert.throws(() => serializeInput(invalidInput), {
      name: 'Error',
      message: 'Invalid input type',
    });
  });
});

test('convertSpecToSerializable', async (t) => {
  await t.test('should serialize a simple Spec', () => {
    const spec = Spec(
      {
        age: Credential.Unsigned(Field),
        isAdmin: Claim(Bool),
        maxAge: Constant(Field, Field(100)),
      },
      ({ age, isAdmin, maxAge }) => ({
        assert: Operation.and(Operation.lessThan(age, maxAge), isAdmin),
        data: age,
      })
    );

    const serialized = convertSpecToSerializable(spec);

    const expected = {
      inputs: {
        age: {
          type: 'credential',
          id: 'none',
          witness: { _type: 'Undefined' },
          data: { _type: 'Field' },
        },
        isAdmin: { type: 'public', data: { _type: 'Bool' } },
        maxAge: { type: 'constant', data: { _type: 'Field' }, value: '100' },
      },
      logic: {
        assert: {
          type: 'and',
          left: {
            type: 'lessThan',
            left: {
              type: 'property',
              key: 'data',
              inner: {
                type: 'property',
                key: 'age',
                inner: { type: 'root' },
              },
            },
            right: {
              type: 'property',
              key: 'maxAge',
              inner: { type: 'root' },
            },
          },
          right: {
            type: 'property',
            key: 'isAdmin',
            inner: { type: 'root' },
          },
        },
        data: {
          type: 'property',
          key: 'data',
          inner: {
            type: 'property',
            key: 'age',
            inner: { type: 'root' },
          },
        },
      },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize a Spec with an credential', () => {
    const spec = Spec(
      {
        signedData: Credential.Simple({ field: Field }),
        zeroField: Constant(Field, Field(0)),
      },
      ({ signedData, zeroField }) => ({
        assert: Operation.equals(
          Operation.property(signedData, 'field'),
          zeroField
        ),
        data: signedData,
      })
    );

    const serialized = convertSpecToSerializable(spec);
    const expected = {
      inputs: {
        signedData: {
          type: 'credential',
          id: 'signature-native',
          witness: {
            type: { type: 'Constant', value: 'simple' },
            issuer: { _type: 'PublicKey' },
            issuerSignature: { _type: 'Signature' },
          },
          data: {
            field: { _type: 'Field' },
          },
        },
        zeroField: { type: 'constant', data: { _type: 'Field' }, value: '0' },
      },
      logic: {
        assert: {
          type: 'equals',
          left: {
            type: 'property',
            key: 'field',
            inner: {
              type: 'property',
              key: 'data',
              inner: {
                type: 'property',
                key: 'signedData',
                inner: { type: 'root' },
              },
            },
          },
          right: {
            type: 'property',
            key: 'zeroField',
            inner: { type: 'root' },
          },
        },
        data: {
          type: 'property',
          key: 'data',
          inner: {
            type: 'property',
            key: 'signedData',
            inner: { type: 'root' },
          },
        },
      },
    };
    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize a Spec with nested operations', () => {
    const spec = Spec(
      {
        field1: Credential.Unsigned(Field),
        field2: Credential.Unsigned(Field),
        zeroField: Constant(Field, Field(0)),
      },
      ({ field1, field2, zeroField }) => ({
        assert: Operation.and(
          Operation.lessThan(field1, field2),
          Operation.equals(field1, zeroField)
        ),
        data: field2,
      })
    );

    const serialized = convertSpecToSerializable(spec);
    const expected = {
      inputs: {
        field1: {
          type: 'credential',
          id: 'none',
          witness: { _type: 'Undefined' },
          data: { _type: 'Field' },
        },
        field2: {
          type: 'credential',
          id: 'none',
          witness: { _type: 'Undefined' },
          data: { _type: 'Field' },
        },
        zeroField: { type: 'constant', data: { _type: 'Field' }, value: '0' },
      },
      logic: {
        assert: {
          type: 'and',
          left: {
            type: 'lessThan',
            left: {
              type: 'property',
              key: 'data',
              inner: {
                type: 'property',
                key: 'field1',
                inner: { type: 'root' },
              },
            },
            right: {
              type: 'property',
              key: 'data',
              inner: {
                type: 'property',
                key: 'field2',
                inner: { type: 'root' },
              },
            },
          },
          right: {
            type: 'equals',
            left: {
              type: 'property',
              key: 'data',
              inner: {
                type: 'property',
                key: 'field1',
                inner: { type: 'root' },
              },
            },
            right: {
              type: 'property',
              key: 'zeroField',
              inner: { type: 'root' },
            },
          },
        },
        data: {
          type: 'property',
          key: 'data',
          inner: {
            type: 'property',
            key: 'field2',
            inner: { type: 'root' },
          },
        },
      },
    };
    assert.deepStrictEqual(serialized, expected);
  });
});

test('Serialize and deserialize spec with hash', async (t) => {
  const spec = Spec(
    {
      age: Credential.Unsigned(Field),
      isAdmin: Claim(Bool),
      ageLimit: Constant(Field, Field(100)),
    },
    ({ age, isAdmin, ageLimit }) => ({
      assert: Operation.and(Operation.lessThan(age, ageLimit), isAdmin),
      data: age,
    })
  );

  const serialized = await serializeSpec(spec);

  await t.test('should include a hash in serialized output', () => {
    const parsed = JSON.parse(serialized);
    assert('hash' in parsed, 'Serialized spec should include a hash');
    assert('spec' in parsed, 'Serialized spec should include the spec string');
    assert(typeof parsed.spec === 'string', 'Spec should be a string');
  });

  await t.test('should validate hash correctly', () => {
    assert(validateSpecHash(serialized), 'Hash should be valid');
  });

  await t.test('should detect tampering', async () => {
    const tampered = JSON.parse(serialized);
    const tamperedSpec = JSON.parse(tampered.spec);
    tamperedSpec.inputs.age.type = 'public';
    tampered.spec = JSON.stringify(tamperedSpec);
    const tamperedString = JSON.stringify(tampered);
    assert(
      !(await validateSpecHash(tamperedString)),
      'Should detect tampered spec'
    );
  });

  await t.test(
    'should throw error on deserialization of tampered spec',
    async () => {
      const tampered = JSON.parse(serialized);
      const tamperedSpec = JSON.parse(tampered.spec);
      tamperedSpec.inputs.age.type = 'public';
      tampered.spec = JSON.stringify(tamperedSpec);
      const tamperedString = JSON.stringify(tampered);

      try {
        await deserializeSpec(tamperedString);
        assert.fail('Expected an error to be thrown');
      } catch (error) {
        assert(error instanceof Error, 'Should throw an Error object');
        assert.strictEqual(
          error.message,
          'Invalid spec hash',
          'Error message should match expected message'
        );
      }
    }
  );
});

test('Serialize spec with owner and issuer nodes', async (t) => {
  const InputData = { age: Field };
  const SignedData = Credential.Simple(InputData);

  const spec = Spec(
    {
      signedData: SignedData,
      targetAge: Claim(Field),
    },
    ({ signedData, targetAge }) => ({
      assert: Operation.equals(
        Operation.property(signedData, 'age'),
        targetAge
      ),
      data: Operation.record({
        owner: Operation.owner,
        issuer: Operation.issuer(signedData),
        age: Operation.property(signedData, 'age'),
      }),
    })
  );

  const serialized = await serializeSpec(spec);
  const parsed = JSON.parse(serialized);
  const serializedSpec = JSON.parse(parsed.spec);

  assert.deepStrictEqual(serializedSpec.logic.data.data.owner, {
    type: 'owner',
  });

  assert.deepStrictEqual(serializedSpec.logic.data.data.issuer, {
    type: 'issuer',
    credentialKey: 'signedData',
  });
});
