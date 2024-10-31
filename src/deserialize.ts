import {
  Field,
  Bool,
  UInt8,
  UInt32,
  UInt64,
  PublicKey,
  Signature,
  type ProvablePure,
  assert,
  Bytes,
  DynamicProof,
  Struct,
} from 'o1js';
import { Claim, Constant, type Input, Node, Spec } from './program-spec.ts';
import type {
  NestedProvable,
  NestedProvableFor,
  NestedProvablePure,
} from './nested.ts';
import {
  validateSpecHash,
  supportedTypes,
  type O1jsTypeName,
  type SerializedType,
  type SerializedContext,
  type SerializedValue,
} from './serialize.ts';
import { type CredentialType } from './credential.ts';
import { Credential } from './credential-index.ts';
import { array, ProvableType } from './o1js-missing.ts';
import { ProvableFactory } from './provable-factory.ts';

export {
  deserializeSpec,
  deserializeInputs,
  deserializeInput,
  deserializeNode,
  deserializeProvableType,
  deserializeProvablePureType,
  deserializeProvable,
  deserializeNestedProvable,
  deserializeNestedProvableValue,
  deserializeInputContext,
  convertSpecFromSerializable,
  replaceNull,
};

function deserializeInputContext(context: null | SerializedContext) {
  if (context === null) return undefined;
  return {
    type: context.type,
    action:
      context.type === 'zk-app'
        ? deserializeProvable({ _type: 'Field', value: context.action.value })
        : context.action,
    serverNonce: deserializeProvable({
      _type: 'Field',
      value: context.serverNonce.value,
    }),
  };
}

async function deserializeSpec(serializedSpecWithHash: string): Promise<Spec> {
  if (!(await validateSpecHash(serializedSpecWithHash))) {
    throw Error('Invalid spec hash');
  }

  const { spec: serializedSpec } = JSON.parse(serializedSpecWithHash);
  return convertSpecFromSerializable(JSON.parse(serializedSpec));
}

function convertSpecFromSerializable(parsedSpec: any): Spec {
  let inputs = deserializeInputs(parsedSpec.inputs);
  return {
    inputs,
    logic: {
      assert: deserializeNode(inputs, parsedSpec.logic.assert),
      outPutClaim: deserializeNode(inputs, parsedSpec.logic.outPutClaim),
    },
  };
}

function deserializeInputs(inputs: Record<string, any>): Record<string, Input> {
  const result: Record<string, Input> = {};
  for (const [key, value] of Object.entries(inputs)) {
    result[key] = deserializeInput(value);
  }
  return result;
}

function deserializeInput(input: any): Input {
  switch (input.type) {
    case 'constant':
      return Constant(
        deserializeProvableType(input.data),
        deserializeProvable({ _type: input.data._type, value: input.value })
      );
    case 'claim':
      return Claim(deserializeNestedProvablePure(input.data));
    case 'credential': {
      let credentialType: CredentialType = input.credentialType;
      let data = deserializeNestedProvablePure(input.data);
      switch (credentialType) {
        case 'simple':
          return Credential.Simple(data);
        case 'unsigned':
          return Credential.Unsigned(data);
        case 'recursive':
          let proof = deserializeProvableType(input.witness.proof) as any;
          return Credential.Recursive(proof, data);
        default:
          throw Error(`Unsupported credential id: ${credentialType}`);
      }
    }
    default:
      throw Error(`Invalid input type: ${input.type}`);
  }
}

function deserializeNode(root: any, node: any): Node;
function deserializeNode(
  root: any,
  node: { type: Node['type'] } & Record<string, any>
): Node {
  switch (node.type) {
    case 'owner': {
      return {
        type: 'owner',
      };
    }
    case 'issuer': {
      return {
        type: 'issuer',
        credentialKey: node.credentialKey,
      };
    }
    case 'constant':
      return {
        type: 'constant',
        data: deserializeProvable(node.data),
      };
    case 'root':
      return { type: 'root', input: root };
    case 'property':
      return {
        type: 'property',
        key: node.key,
        inner: deserializeNode(root, node.inner),
      };
    case 'equals':
    case 'lessThan':
    case 'lessThanEq':
      return {
        type: node.type,
        left: deserializeNode(root, node.left),
        right: deserializeNode(root, node.right),
      };
    case 'equalsOneOf': {
      return {
        type: 'equalsOneOf',
        input: deserializeNode(root, node.input),
        options: Array.isArray(node.options)
          ? node.options.map((o) => deserializeNode(root, o))
          : deserializeNode(root, node.options),
      };
    }
    case 'and':
      return {
        type: node.type,
        inputs: node.inputs.map((i: any) => deserializeNode(root, i)),
      };
    case 'or':
    case 'add':
    case 'sub':
    case 'mul':
    case 'div':
      return {
        type: node.type,
        left: deserializeNode(root, node.left),
        right: deserializeNode(root, node.right),
      };
    case 'hash':
      let result: Node = {
        type: node.type,
        inputs: node.inputs.map((i: any) => deserializeNode(root, i)),
      };
      if (node.prefix !== null) result.prefix = node.prefix;
      return result;
    case 'not':
      return {
        type: node.type,
        inner: deserializeNode(root, node.inner),
      };
    case 'ifThenElse':
      return {
        type: 'ifThenElse',
        condition: deserializeNode(root, node.condition),
        thenNode: deserializeNode(root, node.thenNode),
        elseNode: deserializeNode(root, node.elseNode),
      };
    case 'record':
      const deserializedData: Record<string, Node> = {};
      for (const [key, value] of Object.entries(node.data)) {
        deserializedData[key] = deserializeNode(root, value as any);
      }
      return {
        type: 'record',
        data: deserializedData,
      };
    default:
      throw Error(`Invalid node type: ${node.type}`);
  }
}

function deserializeProvableType(type: SerializedType): ProvableType<any> {
  if (ProvableFactory.isSerialized(type)) return ProvableFactory.fromJSON(type);

  if (type._type === 'Constant') {
    return ProvableType.constant((type as any).value);
  }
  if (type._type === 'Bytes') {
    return Bytes(type.size);
  }
  if (type._type === 'Proof') {
    let proof = type.proof;
    let Proof = class extends DynamicProof<any, any> {
      static publicInputType = deserializeProvablePureType(proof.publicInput);
      static publicOutputType = deserializeProvablePureType(proof.publicOutput);
      static maxProofsVerified = proof.maxProofsVerified;
      static featureFlags = replaceNull(proof.featureFlags) as any;
    };
    Object.defineProperty(Proof, 'name', { value: proof.name });
    return Proof;
  }
  if (type._type === 'Struct') {
    let properties = deserializeNestedProvable(type.properties);
    return Struct(properties);
  }
  if (type._type === 'Array') {
    let inner = deserializeProvableType(type.inner);
    return array(inner, type.size);
  }
  if (type._type === 'String') {
    return String as any;
  }
  let result = supportedTypes[type._type];
  assert(result !== undefined, `Unsupported provable type: ${type._type}`);
  return result;
}

function deserializeProvable(json: SerializedValue): any {
  if (ProvableFactory.isSerialized(json))
    return ProvableFactory.valueFromJSON(json);

  let { _type, value, properties } = json;
  switch (_type) {
    case 'Field':
      return Field.fromJSON(value);
    case 'Bool':
      return Bool(value === 'true');
    case 'UInt8':
      return UInt8.fromJSON({ value });
    case 'UInt32':
      return UInt32.fromJSON(value);
    case 'UInt64':
      return UInt64.fromJSON(value);
    case 'PublicKey':
      return PublicKey.fromJSON(value);
    case 'Signature':
      return Signature.fromJSON(value);
    case 'Bytes':
      return Bytes.fromHex(value);
    case 'Array':
      return (value as any[]).map((v: any) => deserializeProvable(v));
    case 'Struct':
      let type = deserializeProvableType({ _type, properties }) as Struct<any>;
      return type.fromJSON(value);
    default:
      throw Error(`Unsupported provable type: ${_type}`);
  }
}

function deserializeProvablePureType(type: {
  _type: O1jsTypeName;
}): ProvablePure<any> {
  const provableType = deserializeProvableType(type);
  return provableType as ProvablePure<any>;
}

function deserializeNestedProvable(type: any): NestedProvable {
  if (typeof type === 'object' && type !== null) {
    if ('_type' in type) {
      // basic provable type
      return deserializeProvableType(type);
    } else {
      // nested object
      const result: Record<string, any> = {};
      for (const [key, value] of Object.entries(type)) {
        result[key] = deserializeNestedProvable(value);
      }
      return result as NestedProvableFor<any>;
    }
  }
  throw Error(`Invalid type in NestedProvable: ${type}`);
}

function deserializeNestedProvablePure(type: any): NestedProvablePure {
  if (typeof type === 'object' && type !== null) {
    if ('_type' in type) {
      // basic provable pure type
      return deserializeProvablePureType(type);
    } else {
      // nested object
      const result: Record<string, any> = {};
      for (const [key, value] of Object.entries(type)) {
        result[key] = deserializeNestedProvablePure(value);
      }
      return result as NestedProvablePure;
    }
  }
  throw Error(`Invalid type in NestedProvablePure: ${type}`);
}

function deserializeNestedProvableValue(value: any): any {
  if (typeof value === 'string') return value;

  if (typeof value === 'object' && value !== null) {
    if ('_type' in value) {
      // basic provable type
      return deserializeProvable(value);
    } else {
      // nested object
      const result: Record<string, any> = {};
      for (let [key, v] of Object.entries(value)) {
        result[key] = deserializeNestedProvableValue(v);
      }
      return result;
    }
  }

  throw Error(`Invalid nested provable value: ${value}`);
}

function replaceNull(obj: Record<string, any>): Record<string, any> {
  return Object.fromEntries(
    Object.entries(obj).map(([key, value]) => [
      key,
      value === null ? undefined : value,
    ])
  );
}
