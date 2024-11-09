import { Bool, UInt8, UInt32, UInt64, Field, Provable, PublicKey } from 'o1js';
import { ProvableType } from './o1js-missing.ts';
import { assert, assertHasProperty } from './util.ts';
import { NestedProvable } from './nested.ts';
import { DynamicArray } from './credentials/dynamic-array.ts';
import {
  DynamicRecord,
  extractProperty,
} from './credentials/dynamic-record.ts';
import { hashDynamicWithPrefix } from './credentials/dynamic-hash.ts';
import type { Input } from './program-spec.ts';

export { Node, Operation };
export { type GetData, root };

const Operation = {
  owner: { type: 'owner' } as Node<PublicKey>,
  issuer,
  property,
  record,
  equals,
  equalsOneOf,
  lessThan,
  lessThanEq,
  add,
  sub,
  mul,
  div,
  and,
  or,
  not,
  hash,
  hashWithPrefix,
  ifThenElse,
  compute,
};

type Node<Data = any> =
  | { type: 'owner' }
  | { type: 'issuer'; credentialKey: string }
  | { type: 'constant'; data: Data }
  | { type: 'root'; input: Record<string, Input> }
  | { type: 'property'; key: string; inner: Node }
  | { type: 'record'; data: Record<string, Node> }
  | { type: 'equals'; left: Node; right: Node }
  | {
      type: 'equalsOneOf';
      input: Node;
      options: Node[] | Node<any[]> | Node<DynamicArray>;
    }
  | { type: 'lessThan'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'lessThanEq'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'add'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'sub'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'mul'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'div'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'and'; inputs: Node<Bool>[] }
  | { type: 'or'; left: Node<Bool>; right: Node<Bool> }
  | { type: 'not'; inner: Node<Bool> }
  | { type: 'hash'; inputs: Node[]; prefix?: string }
  | {
      type: 'ifThenElse';
      condition: Node<Bool>;
      thenNode: Node;
      elseNode: Node;
    }
  | {
      type: 'compute';
      inputs: readonly Node[];
      computation: (...inputs: any[]) => any;
      outputType: ProvableType;
    };

type GetData<T extends Input> = T extends Input<infer Data> ? Data : never;

const Node = {
  eval: evalNode,
  evalType: evalNodeType,

  constant<Data>(data: Data): Node<Data> {
    return { type: 'constant', data };
  },
};

function evalNode<Data>(root: object, node: Node<Data>): Data {
  switch (node.type) {
    case 'owner':
      return (root as any).owner;
    case 'issuer':
      assertHasProperty(root, node.credentialKey);
      const credential = (root as any)[node.credentialKey];
      return credential.issuer;
    case 'constant':
      return node.data;
    case 'root':
      return root as any;
    case 'property': {
      let inner = evalNode<unknown>(root, node.inner);
      if (
        inner &&
        typeof inner === 'object' &&
        'credential' in inner &&
        'issuer' in inner
      ) {
        return extractProperty(inner.credential, node.key) as Data;
      } else {
        return extractProperty(inner, node.key) as Data;
      }
    }
    case 'record': {
      let result: Record<string, any> = {};
      for (let key in node.data) {
        result[key] = evalNode(root, node.data[key]!);
      }
      return result as any;
    }
    case 'equals': {
      let left = evalNode(root, node.left);
      let right = evalNode(root, node.right);
      let bool = Provable.equal(ProvableType.fromValue(left), left, right);
      return bool as Data;
    }
    case 'equalsOneOf': {
      let input = evalNode(root, node.input);
      let type = NestedProvable.get(NestedProvable.fromValue(input));
      let options: any[] | DynamicArray;
      if (Array.isArray(node.options)) {
        options = node.options.map((i) => evalNode(root, i));
      } else {
        options = evalNode<any[] | DynamicArray>(root, node.options);
      }
      if (options instanceof DynamicArray.Base) {
        let bool = options.reduce(Bool, Bool(false), (acc, o) =>
          acc.or(Provable.equal(type, input, o))
        );
        return bool as Data;
      }
      let bools = options.map((o) => Provable.equal(type, input, o));
      return bools.reduce(Bool.or) as Data;
    }
    case 'lessThan':
    case 'lessThanEq':
      return compareNodes(root, node, node.type === 'lessThanEq') as Data;
    case 'add':
    case 'sub':
    case 'mul':
    case 'div':
      return arithmeticOperation(root, node) as Data;
    case 'and': {
      let inputs = node.inputs.map((i) => evalNode(root, i));
      return inputs.reduce(Bool.and) as Data;
    }
    case 'or': {
      let left = evalNode(root, node.left);
      let right = evalNode(root, node.right);
      return left.or(right) as Data;
    }
    case 'not': {
      let inner = evalNode(root, node.inner);
      return inner.not() as Data;
    }
    case 'hash': {
      let inputs = node.inputs.map((i) => evalNode(root, i));
      return hashDynamicWithPrefix(node.prefix, ...inputs) as Data;
    }
    case 'ifThenElse': {
      let condition = evalNode(root, node.condition);
      let thenNode = evalNode(root, node.thenNode);
      let elseNode = evalNode(root, node.elseNode);
      let result = Provable.if(condition, thenNode, elseNode);
      return result as Data;
    }
    case 'compute': {
      const computationInputs = node.inputs.map((input) =>
        evalNode(root, input)
      );
      return node.computation(...computationInputs);
    }
  }
}

function arithmeticOperation(
  root: object,
  node: {
    type: 'add' | 'sub' | 'mul' | 'div';
    left: Node<NumericType>;
    right: Node<NumericType>;
  }
): NumericType {
  let left = evalNode(root, node.left);
  let right = evalNode(root, node.right);

  const [leftConverted, rightConverted] = convertNodes(left, right);

  switch (node.type) {
    case 'add':
      return leftConverted.add(rightConverted as any);
    case 'sub':
      return leftConverted.sub(rightConverted as any);
    case 'mul':
      return leftConverted.mul(rightConverted as any);
    case 'div':
      return leftConverted.div(rightConverted as any);
  }
}

function compareNodes(
  root: object,
  node: { left: Node<any>; right: Node<any> },
  allowEqual: boolean
): Bool {
  let left = evalNode(root, node.left);
  let right = evalNode(root, node.right);

  const [leftConverted, rightConverted] = convertNodes(left, right);

  return allowEqual
    ? leftConverted.lessThanOrEqual(rightConverted as any)
    : leftConverted.lessThan(rightConverted as any);
}

function convertNodes(left: any, right: any): [NumericType, NumericType] {
  const leftTypeIndex = numericTypeOrder.findIndex(
    (type) => left instanceof type
  );
  const rightTypeIndex = numericTypeOrder.findIndex(
    (type) => right instanceof type
  );

  const resultType = numericTypeOrder[Math.max(leftTypeIndex, rightTypeIndex)];

  const leftConverted =
    leftTypeIndex < rightTypeIndex
      ? resultType === Field
        ? left.toField()
        : resultType === UInt64
        ? left.toUInt64()
        : left.toUInt32()
      : left;

  const rightConverted =
    leftTypeIndex > rightTypeIndex
      ? resultType === Field
        ? right.toField()
        : resultType === UInt64
        ? right.toUInt64()
        : right.toUInt32()
      : right;

  return [leftConverted, rightConverted];
}

function evalNodeType(rootType: NestedProvable, node: Node): NestedProvable {
  switch (node.type) {
    case 'constant':
      return ProvableType.fromValue(node.data);
    case 'root':
      return rootType;
    case 'property': {
      // TODO would be nice to get inner types of structs more easily
      let inner = evalNodeType(rootType, node.inner);

      // case 1: inner is a provable type
      if (ProvableType.isProvableType(inner)) {
        let innerValue = ProvableType.synthesize(inner);
        assertHasProperty(innerValue, node.key);
        let value = innerValue[node.key];
        return ProvableType.fromValue(value);
      }
      // case 2: inner is a record of provable types
      return inner[node.key] as any;
    }
    case 'equals':
    case 'equalsOneOf':
    case 'lessThan':
    case 'lessThanEq':
    case 'and':
    case 'or':
    case 'not':
      return Bool;
    case 'owner':
      return PublicKey;
    case 'hash':
    case 'issuer':
      return Field;
    case 'add':
    case 'sub':
    case 'mul':
    case 'div':
      return ArithmeticOperationType(rootType, node);
    case 'ifThenElse':
      return Node as any;
    case 'record': {
      let result: Record<string, NestedProvable> = {};
      for (let key in node.data) {
        result[key] = evalNodeType(rootType, node.data[key]!);
      }
      return result;
    }
    case 'compute': {
      return node.outputType;
    }
  }
}

function ArithmeticOperationType(
  rootType: NestedProvable,
  node: { left: Node<NumericType>; right: Node<NumericType> }
): NestedProvable {
  const leftType = evalNodeType(rootType, node.left);
  const rightType = evalNodeType(rootType, node.right);
  const leftTypeIndex = numericTypeOrder.findIndex((type) => leftType === type);
  const rightTypeIndex = numericTypeOrder.findIndex(
    (type) => rightType === type
  );
  return numericTypeOrder[Math.max(leftTypeIndex, rightTypeIndex)] as any;
}

// Node constructors

function root<Inputs extends Record<string, Input>>(
  inputs: Inputs
): Node<{ [K in keyof Inputs]: Node<GetData<Inputs[K]>> }> {
  return { type: 'root', input: inputs };
}

function property<K extends string, Data extends { [key in K]: any }>(
  node: Node<Data | DynamicRecord<Data>>,
  key: K
): Node<Data[K]> {
  return { type: 'property', key, inner: node as Node<any> };
}

function record<Nodes extends Record<string, Node>>(
  nodes: Nodes
): Node<{
  [K in keyof Nodes]: Nodes[K] extends Node<infer Data> ? Data : never;
}> {
  return { type: 'record', data: nodes };
}

function equals<Data>(left: Node<Data>, right: Node<Data>): Node<Bool> {
  return { type: 'equals', left, right };
}

function equalsOneOf<Data>(
  input: Node<Data>,
  options: Node<Data>[] | Node<Data[]> | Node<DynamicArray<Data>>
): Node<Bool> {
  return { type: 'equalsOneOf', input, options };
}

type NumericType = Field | UInt64 | UInt32 | UInt8;

const numericTypeOrder = [UInt8, UInt32, UInt64, Field];

function lessThan<Left extends NumericType, Right extends NumericType>(
  left: Node<Left>,
  right: Node<Right>
): Node<Bool> {
  return { type: 'lessThan', left, right };
}

function lessThanEq<Left extends NumericType, Right extends NumericType>(
  left: Node<Left>,
  right: Node<Right>
): Node<Bool> {
  return { type: 'lessThanEq', left, right };
}

function add<Left extends NumericType, Right extends NumericType>(
  left: Node<Left>,
  right: Node<Right>
): Node<Left | Right> {
  return { type: 'add', left, right };
}

function sub<Left extends NumericType, Right extends NumericType>(
  left: Node<Left>,
  right: Node<Right>
): Node<Left | Right> {
  return { type: 'sub', left, right };
}

function mul<Left extends NumericType, Right extends NumericType>(
  left: Node<Left>,
  right: Node<Right>
): Node<Left | Right> {
  return { type: 'mul', left, right };
}

function div<Left extends NumericType, Right extends NumericType>(
  left: Node<Left>,
  right: Node<Right>
): Node<Left | Right> {
  return { type: 'div', left, right };
}

function and(...inputs: Node<Bool>[]): Node<Bool> {
  return { type: 'and', inputs };
}

function or(left: Node<Bool>, right: Node<Bool>): Node<Bool> {
  return { type: 'or', left, right };
}

function not(inner: Node<Bool>): Node<Bool> {
  return { type: 'not', inner };
}

function hash(...inputs: Node[]): Node<Field> {
  return { type: 'hash', inputs };
}
function hashWithPrefix(prefix: string, ...inputs: Node[]): Node<Field> {
  return { type: 'hash', inputs, prefix };
}

function issuer(credential: Node): Node<Field> {
  let msg = 'Can only get issuer for a credential';
  assert(credential.type === 'property', msg);
  assert(credential.key === 'data', msg);
  assert(credential.inner.type === 'property', msg);
  return { type: 'issuer', credentialKey: credential.inner.key };
}

function ifThenElse<Data>(
  condition: Node<Bool>,
  thenNode: Node<Data>,
  elseNode: Node<Data>
): Node<Data> {
  return { type: 'ifThenElse', condition, thenNode, elseNode };
}

function compute<Inputs extends readonly Node[], Output>(
  inputs: [...Inputs],
  outputType: ProvableType<Output>,
  computation: (
    ...args: {
      [K in keyof Inputs]: Inputs[K] extends Node<infer T> ? T : never;
    }
  ) => Output
): Node<Output> {
  return {
    type: 'compute',
    inputs: inputs,
    computation: computation as (inputs: any[]) => Output,
    outputType,
  };
}
