import {
  Bool,
  UInt8,
  UInt32,
  UInt64,
  Field,
  Provable,
  type ProvablePure,
  Poseidon,
} from 'o1js';
import type { ExcludeFromRecord } from './types.ts';
import {
  assertPure,
  type InferProvableType,
  ProvableType,
} from './o1js-missing.ts';
import { assertHasProperty } from './util.ts';
import {
  type InferNestedProvable,
  NestedProvable,
  type NestedProvableFor,
  type NestedProvablePure,
  type NestedProvablePureFor,
} from './nested.ts';
import { Credential, type CredentialId } from './credentials.ts';

export type { PublicInputs, UserInputs };
export {
  Spec,
  Node,
  Operation,
  Input,
  publicInputTypes,
  publicOutputType,
  privateInputTypes,
  splitUserInputs,
  verifyCredentials,
  recombineDataInputs,
};

type Spec<
  Data = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = {
  inputs: Inputs;
  logic: Required<OutputNode<Data>>;
};

/**
 * Specify a ZkProgram that verifies and selectively discloses data
 */
function Spec<Data, Inputs extends Record<string, Input>>(
  inputs: Inputs,
  spec: (inputs: {
    [K in keyof Inputs]: Node<GetData<Inputs[K]>>;
  }) => {
    assert?: Node<Bool>;
    data: Node<Data>;
  }
): Spec<Data, Inputs>;

// variant without data output
function Spec<Inputs extends Record<string, Input>>(
  inputs: Inputs,
  spec: (inputs: {
    [K in keyof Inputs]: Node<GetData<Inputs[K]>>;
  }) => {
    assert?: Node<Bool>;
  }
): Spec<undefined, Inputs>;

// implementation
function Spec<Data, Inputs extends Record<string, Input>>(
  inputs: Inputs,
  spec: (inputs: {
    [K in keyof Inputs]: Node<GetData<Inputs[K]>>;
  }) => OutputNode<Data>
): Spec<Data, Inputs> {
  let rootNode = root(inputs);
  let inputNodes: {
    [K in keyof Inputs]: Node<GetData<Inputs[K]>>;
  } = {} as any;
  for (let key in inputs) {
    inputNodes[key] = property(rootNode, key) as any;
  }
  let logic = spec(inputNodes);
  let assert = logic.assert ?? Node.constant(Bool(true));
  let data: Node<Data> = logic.data ?? (Node.constant(undefined) as any);

  return { inputs, logic: { assert, data } };
}

const Input = {
  public: publicParameter,
  private: privateParameter,
  constant,
};

const Operation = {
  property,
  equals,
  lessThan,
  lessThanEq,
  add,
  and,
  or,
  not,
  hash,
  ifThenElse,
};

type Constant<Data> = {
  type: 'constant';
  data: ProvableType<Data>;
  value: Data;
};
type Public<Data> = { type: 'public'; data: NestedProvablePureFor<Data> };
type Private<Data> = { type: 'private'; data: NestedProvableFor<Data> };

type Input<Data = any> =
  | Credential<CredentialId, any, any, Data>
  | Constant<Data>
  | Public<Data>
  | Private<Data>;

type Node<Data = any> =
  | { type: 'constant'; data: Data }
  | { type: 'root'; input: Record<string, Input> }
  | { type: 'property'; key: string; inner: Node }
  | { type: 'equals'; left: Node; right: Node }
  | { type: 'lessThan'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'lessThanEq'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'add'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'and'; left: Node<Bool>; right: Node<Bool> }
  | { type: 'or'; left: Node<Bool>; right: Node<Bool> }
  | { type: 'not'; inner: Node<Bool> }
  | { type: 'hash'; inner: Node }
  | {
      type: 'ifThenElse';
      condition: Node<Bool>;
      thenNode: Node;
      elseNode: Node;
    };

type OutputNode<Data = any> = {
  assert?: Node<Bool>;
  data?: Node<Data>;
};

const Node = {
  eval: evalNode,
  evalType: evalNodeType,

  constant<Data>(data: Data): Node<Data> {
    return { type: 'constant', data };
  },
};

function evalNode<Data>(root: object, node: Node<Data>): Data {
  switch (node.type) {
    case 'constant':
      return node.data;
    case 'root':
      return root as any;
    case 'property': {
      let inner = evalNode<unknown>(root, node.inner);
      assertHasProperty(inner, node.key);
      return inner[node.key] as Data;
    }
    case 'equals': {
      let left = evalNode(root, node.left);
      let right = evalNode(root, node.right);
      let bool = Provable.equal(ProvableType.fromValue(left), left, right);
      return bool as Data;
    }
    case 'lessThan':
    case 'lessThanEq':
      return compareNodes(root, node, node.type === 'lessThanEq') as Data;
    case 'add': {
      return addNodes(root, node) as Data;
    }
    case 'and': {
      let left = evalNode(root, node.left);
      let right = evalNode(root, node.right);
      return left.and(right) as Data;
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
      let inner = evalNode(root, node.inner);
      let innerFields = inner.toFields();
      let hash = Poseidon.hash(innerFields);
      return hash as Data;
    }
    case 'ifThenElse': {
      let condition = evalNode(root, node.condition);
      let thenNode = evalNode(root, node.thenNode);
      let elseNode = evalNode(root, node.elseNode);
      let result = Provable.if(condition, thenNode, elseNode);
      return result as Data;
    }
  }
}

function addNodes(
  root: object,
  node: { left: Node<NumericType>; right: Node<NumericType> }
): NumericType {
  let left = evalNode(root, node.left);
  let right = evalNode(root, node.right);

  const [leftConverted, rightConverted] = convertNodes(left, right);

  return leftConverted.add(rightConverted as any);
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

function evalNodeType<Data>(
  rootType: NestedProvable,
  node: Node<Data>
): NestedProvable {
  switch (node.type) {
    case 'constant':
      return ProvableType.fromValue(node.data);
    case 'root':
      return rootType;
    case 'property': {
      // TODO would be nice to get inner types of structs more easily
      let inner = evalNodeType<unknown>(rootType, node.inner);

      // case 1: inner is a provable type
      if (ProvableType.isProvableType(inner)) {
        let innerValue = ProvableType.synthesize(inner);
        assertHasProperty(innerValue, node.key);
        let value: Data = innerValue[node.key] as any;
        return ProvableType.fromValue(value);
      }
      // case 2: inner is a record of provable types
      return inner[node.key] as any;
    }
    case 'equals': {
      return Bool as any;
    }
    case 'lessThan': {
      return Bool as any;
    }
    case 'lessThanEq': {
      return Bool as any;
    }
    case 'add': {
      const leftType = evalNodeType(rootType, node.left);
      const rightType = evalNodeType(rootType, node.right);
      const leftTypeIndex = numericTypeOrder.findIndex(
        (type) => leftType === type
      );
      const rightTypeIndex = numericTypeOrder.findIndex(
        (type) => rightType === type
      );
      return numericTypeOrder[Math.max(leftTypeIndex, rightTypeIndex)] as any;
    }
    case 'and': {
      return Bool as any;
    }
    case 'or': {
      return Bool as any;
    }
    case 'not': {
      return Bool as any;
    }
    case 'hash': {
      return Field as any;
    }
    case 'ifThenElse': {
      return Node as any;
    }
  }
}

type GetData<T extends Input> = T extends Input<infer Data> ? Data : never;

function constant<DataType extends ProvableType>(
  data: DataType,
  value: InferProvableType<DataType>
): Constant<InferProvableType<DataType>> {
  return { type: 'constant', data, value };
}

function publicParameter<DataType extends NestedProvablePure>(
  data: DataType
): Public<InferNestedProvable<DataType>> {
  return { type: 'public', data: data as any };
}

function privateParameter<DataType extends NestedProvable>(
  data: DataType
): Private<InferNestedProvable<DataType>> {
  return { type: 'private', data: data as any };
}

// Node constructors

function root<Inputs extends Record<string, Input>>(
  inputs: Inputs
): Node<{ [K in keyof Inputs]: Node<GetData<Inputs[K]>> }> {
  return { type: 'root', input: inputs };
}

function property<K extends string, Data extends { [key in K]: any }>(
  node: Node<Data>,
  key: K
): Node<Data[K]> {
  return { type: 'property', key, inner: node as Node<any> };
}

function equals<Data>(left: Node<Data>, right: Node<Data>): Node<Bool> {
  return { type: 'equals', left, right };
}

type NumericType = Field | UInt64 | UInt32 | UInt8;
const numericTypeOrder = [UInt8, UInt32, UInt64, Field];

function lessThan<Data extends NumericType>(
  left: Node<Data>,
  right: Node<Data>
): Node<Bool> {
  return { type: 'lessThan', left, right };
}

function lessThanEq<Data extends NumericType>(
  left: Node<Data>,
  right: Node<Data>
): Node<Bool> {
  return { type: 'lessThanEq', left, right };
}

function add<Data extends NumericType>(
  left: Node<Data>,
  right: Node<Data>
): Node<Data> {
  return { type: 'add', left, right };
}

function and(left: Node<Bool>, right: Node<Bool>): Node<Bool> {
  return { type: 'and', left, right };
}

function or(left: Node<Bool>, right: Node<Bool>): Node<Bool> {
  return { type: 'or', left, right };
}

function not(inner: Node<Bool>): Node<Bool> {
  return { type: 'not', inner };
}

function hash(inner: Node): Node<Field> {
  return { type: 'hash', inner };
}

function ifThenElse(
  condition: Node<Bool>,
  thenNode: Node,
  elseNode: Node
): Node {
  return { type: 'ifThenElse', condition, thenNode, elseNode };
}

function publicInputTypes<S extends Spec>({
  inputs,
}: S): Record<string, NestedProvablePure> {
  let result: Record<string, NestedProvablePure> = {};

  Object.entries(inputs).forEach(([key, input]) => {
    if (input.type === 'credential') {
      result[key] = input.public;
    }
    if (input.type === 'public') {
      result[key] = input.data;
    }
  });
  return result;
}

function privateInputTypes<S extends Spec>({
  inputs,
}: S): Record<string, NestedProvable> {
  let result: Record<string, NestedProvable> = {};

  Object.entries(inputs).forEach(([key, input]) => {
    if (input.type === 'credential') {
      result[key] = { private: input.private, data: input.data };
    }
    if (input.type === 'private') {
      result[key] = input.data;
    }
  });
  return result;
}

function publicOutputType<S extends Spec>(spec: S): ProvablePure<any> {
  let root = dataInputTypes(spec);
  let outputTypeNested = Node.evalType(root, spec.logic.data);
  let outputType = NestedProvable.get(outputTypeNested);
  assertPure(outputType);
  return outputType;
}

function dataInputTypes<S extends Spec>({ inputs }: S): NestedProvable {
  let result: Record<string, NestedProvable> = {};
  Object.entries(inputs).forEach(([key, input]) => {
    result[key] = input.data;
  });
  return result;
}

function splitUserInputs<S extends Spec>(
  spec: S,
  userInputs: Record<string, any>
): {
  publicInput: PublicInputs<S['inputs']>;
  privateInput: PrivateInputs<S['inputs']>;
};
function splitUserInputs<S extends Spec>(
  spec: S,
  userInputs: Record<string, any>
): { publicInput: Record<string, any>; privateInput: Record<string, any> } {
  let publicInput: Record<string, any> = {};
  let privateInput: Record<string, any> = {};

  Object.entries(spec.inputs).forEach(([key, input]) => {
    if (input.type === 'credential') {
      publicInput[key] = userInputs[key].public;
      privateInput[key] = {
        private: userInputs[key].private,
        data: userInputs[key].data,
      };
    }
    if (input.type === 'public') {
      publicInput[key] = userInputs[key];
    }
    if (input.type === 'private') {
      privateInput[key] = userInputs[key];
    }
    if (input.type === 'constant') {
      // do nothing
    }
  });
  return { publicInput, privateInput };
}

function verifyCredentials<S extends Spec>(
  spec: S,
  publicInputs: Record<string, any>,
  privateInputs: Record<string, any>
) {
  Object.entries(spec.inputs).forEach(([key, input]) => {
    if (input.type === 'credential') {
      let publicInput = publicInputs[key];
      let { private: privateInput, data } = privateInputs[key];
      input.verify(publicInput, privateInput, data);
    }
  });
}

function recombineDataInputs<S extends Spec>(
  spec: S,
  publicInputs: Record<string, any>,
  privateInputs: Record<string, any>
): DataInputs<S['inputs']>;
function recombineDataInputs<S extends Spec>(
  spec: S,
  publicInputs: Record<string, any>,
  privateInputs: Record<string, any>
): Record<string, any> {
  let result: Record<string, any> = {};

  Object.entries(spec.inputs).forEach(([key, input]) => {
    if (input.type === 'credential') {
      result[key] = privateInputs[key].data;
    }
    if (input.type === 'public') {
      result[key] = publicInputs[key];
    }
    if (input.type === 'private') {
      result[key] = privateInputs[key];
    }
    if (input.type === 'constant') {
      result[key] = input.value;
    }
  });
  return result;
}

type PublicInputs<Inputs extends Record<string, Input>> = ExcludeFromRecord<
  MapToPublic<Inputs>,
  never
>;

type PrivateInputs<Inputs extends Record<string, Input>> = ExcludeFromRecord<
  MapToPrivate<Inputs>,
  never
>;

type UserInputs<Inputs extends Record<string, Input>> = ExcludeFromRecord<
  MapToUserInput<Inputs>,
  never
>;

type DataInputs<Inputs extends Record<string, Input>> = ExcludeFromRecord<
  MapToDataInput<Inputs>,
  never
>;

type MapToPublic<T extends Record<string, Input>> = {
  [K in keyof T]: ToPublic<T[K]>;
};

type MapToPrivate<T extends Record<string, Input>> = {
  [K in keyof T]: ToPrivate<T[K]>;
};

type MapToUserInput<T extends Record<string, Input>> = {
  [K in keyof T]: ToUserInput<T[K]>;
};

type MapToDataInput<T extends Record<string, Input>> = {
  [K in keyof T]: ToDataInput<T[K]>;
};

type ToPublic<T extends Input> = T extends Credential<
  CredentialId,
  infer Public,
  any,
  any
>
  ? Public
  : T extends Public<infer Data>
  ? Data
  : never;

type ToPrivate<T extends Input> = T extends Credential<
  CredentialId,
  any,
  infer Private,
  infer Data
>
  ? { private: Private; data: Data }
  : T extends Private<infer Data>
  ? Data
  : never;

type ToUserInput<T extends Input> = T extends Credential<
  CredentialId,
  infer Public,
  infer Private,
  infer Data
>
  ? { public: Public; private: Private; data: Data }
  : T extends Public<infer Data>
  ? Data
  : T extends Private<infer Data>
  ? Data
  : never;

type ToDataInput<T extends Input> = T extends Input<infer Data> ? Data : never;
