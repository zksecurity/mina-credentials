import { test } from 'node:test';
import assert from 'node:assert';
import { Credential } from '../src/credential-index.ts';
import {
  StoredCredentialSchema,
  NodeSchema,
  InputSchema,
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
import { serializeInput, serializeNode } from '../src/serialize.ts';

const Bytes32 = Bytes(32);

// test('StoredCredentialSchema validation', async (t) => {
//   await t.test('validates simple credential', () => {
//     const data = { age: Field(25) };
//     const signedCredential = Credential.sign(issuerKey, { owner, data });
//     const serialized = Credential.toJSON(signedCredential);
//     const parsed = JSON.parse(serialized);

//     const result = StoredCredentialSchema.safeParse(parsed);
//     assert(
//       result.success,
//       'Simple credential JSON should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('validates recursive credential', async () => {
//     const InputData = { age: Field, name: Bytes32 };
//     const inputProofSpec = Spec(
//       { inputOwner: Claim(PublicKey), data: Claim(InputData) },
//       ({ inputOwner, data }) => ({
//         outPutClaim: Operation.record({ owner: inputOwner, data }),
//       })
//     );

//     // create recursive credential
//     const Recursive = await Credential.Recursive.fromProgram(
//       createProgram(inputProofSpec)
//     );
//     let data = { age: Field(18), name: Bytes32.fromString('Alice') };
//     let provedData = await Recursive.create({
//       claims: { inputOwner: owner, data },
//       credentials: {},
//       context: Field(0), // dummy context
//       ownerSignature: Signature.empty(), // no credential => no signature verification
//     });

//     const serialized = Credential.toJSON(provedData);
//     const parsed = JSON.parse(serialized);

//     const result = StoredCredentialSchema.safeParse(parsed);
//     assert(
//       result.success,
//       'Recursive credential JSON should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate a valid unsigned credential', () => {
//     const unsignedCredential = createUnsigned({
//       age: Field(42),
//       name: Bytes32.fromString('Alice'),
//     });

//     const serialized = Credential.toJSON(unsignedCredential);
//     const parsed = JSON.parse(serialized);

//     const result = StoredCredentialSchema.safeParse(parsed);
//     assert(
//       result.success,
//       'Unsigned credential JSON should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });
// });

// test('NodeSchema validation', async (t) => {
//   await t.test('should validate constant Node', () => {
//     const constantNode: Node<Field> = { type: 'constant', data: Field(123) };

//     const serialized = serializeNode(constantNode);
//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate property Node', () => {
//     const propertyNode: Node = {
//       type: 'property',
//       key: 'age',
//       inner: {
//         type: 'root',
//         input: {
//           age: Credential.Unsigned(Field),
//           isAdmin: Claim(Bool),
//         },
//       },
//     };

//     const serialized = serializeNode(propertyNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate equals Node', () => {
//     const equalsNode: Node<Bool> = Operation.equals(
//       { type: 'constant', data: Field(10) },
//       { type: 'constant', data: Field(10) }
//     );

//     const serialized = serializeNode(equalsNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate lessThan Node', () => {
//     const lessThanNode: Node<Bool> = Operation.lessThan(
//       { type: 'constant', data: UInt32.from(5) },
//       { type: 'constant', data: UInt32.from(10) }
//     );

//     const serialized = serializeNode(lessThanNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate lessThanEq Node', () => {
//     const lessThanEqNode: Node<Bool> = Operation.lessThanEq(
//       { type: 'constant', data: UInt64.from(15) },
//       { type: 'constant', data: UInt64.from(15) }
//     );

//     const serialized = serializeNode(lessThanEqNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate and Node', () => {
//     const andNode: Node<Bool> = Operation.and(
//       { type: 'constant', data: Bool(true) },
//       { type: 'constant', data: Bool(false) }
//     );

//     const serialized = serializeNode(andNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate or Node', () => {
//     const orNode: Node<Bool> = Operation.or(
//       { type: 'constant', data: Bool(true) },
//       { type: 'constant', data: Bool(false) }
//     );

//     const serialized = serializeNode(orNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate add Node', () => {
//     const addNode: Node<Field> = Operation.add(
//       { type: 'constant', data: Field(5) },
//       { type: 'constant', data: Field(10) }
//     );

//     const serialized = serializeNode(addNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate sub Node', () => {
//     const subNode: Node<Field> = Operation.sub(
//       { type: 'constant', data: Field(15) },
//       { type: 'constant', data: Field(7) }
//     );

//     const serialized = serializeNode(subNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate mul Node', () => {
//     const mulNode: Node<Field> = Operation.mul(
//       { type: 'constant', data: Field(3) },
//       { type: 'constant', data: Field(4) }
//     );

//     const serialized = serializeNode(mulNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate div Node', () => {
//     const divNode: Node<Field> = Operation.div(
//       { type: 'constant', data: Field(20) },
//       { type: 'constant', data: Field(5) }
//     );

//     const serialized = serializeNode(divNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate not Node', () => {
//     const notNode: Node<Bool> = Operation.not({
//       type: 'constant',
//       data: Bool(true),
//     });

//     const serialized = serializeNode(notNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate hash Node', () => {
//     const hashNode: Node<Field> = Operation.hash({
//       type: 'constant',
//       data: Field(123),
//     });

//     const serialized = serializeNode(hashNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate ifThenElse Node', () => {
//     const ifThenElseNode: Node<Field> = Operation.ifThenElse(
//       { type: 'constant', data: Bool(true) },
//       { type: 'constant', data: Field(1) },
//       { type: 'constant', data: Field(0) }
//     );

//     const serialized = serializeNode(ifThenElseNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate record Node', () => {
//     const recordNode: Node = Operation.record({
//       field1: { type: 'constant', data: Field(123) },
//       field2: { type: 'constant', data: Bool(true) },
//     });

//     const serialized = serializeNode(recordNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate nested Nodes', () => {
//     const nestedNode: Node<Bool> = Operation.and(
//       Operation.lessThan(
//         { type: 'constant', data: Field(5) },
//         { type: 'constant', data: Field(10) }
//       ),
//       Operation.equals(
//         { type: 'constant', data: Bool(true) },
//         { type: 'constant', data: Bool(true) }
//       )
//     );

//     const serialized = serializeNode(nestedNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test('should validate equalsOneOf Node with array options', () => {
//     const options: Node<Field>[] = [
//       { type: 'constant', data: Field(10) },
//       { type: 'constant', data: Field(20) },
//       { type: 'constant', data: Field(30) },
//     ];

//     const equalsOneOfNode: Node<Bool> = Operation.equalsOneOf(
//       { type: 'constant', data: Field(20) },
//       options
//     );

//     const serialized = serializeNode(equalsOneOfNode);

//     const result = NodeSchema.safeParse(serialized);

//     assert(
//       result.success,
//       'Node should be valid with array options: ' +
//         (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//     );
//   });

//   await t.test(
//     'should validate equalsOneOf Node with single node options',
//     () => {
//       const optionsNode: Node<Field[]> = {
//         type: 'constant',
//         data: [Field(10), Field(20), Field(30)],
//       };

//       const equalsOneOfNode: Node<Bool> = Operation.equalsOneOf(
//         { type: 'constant', data: Field(20) },
//         optionsNode
//       );

//       const serialized = serializeNode(equalsOneOfNode);

//       const result = NodeSchema.safeParse(serialized);

//       assert(
//         result.success,
//         'Node should be valid with single node options: ' +
//           (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
//       );
//     }
//   );
// });

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
