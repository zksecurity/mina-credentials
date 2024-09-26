import {
  assert,
  Bool,
  Bytes,
  Field,
  PrivateKey,
  Provable,
  PublicKey,
  Signature,
  Struct,
  Undefined,
  VerificationKey,
  type ProvablePure,
} from 'o1js';
import type { ExcludeFromRecord } from './types.ts';
import {
  assertPure,
  type InferProvableType,
  type ProvablePureType,
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

/**
 * TODO: program spec must be serializable
 * - can be done by defining an enum of supported base types
 */

export type { PublicInputs, UserInputs };
export {
  Spec,
  Node,
  Attestation,
  Operation,
  Input,
  publicInputTypes,
  publicOutputType,
  privateInputTypes,
  splitUserInputs,
  verifyAttestations,
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

const Undefined_: ProvablePure<undefined> = Undefined;

/**
 * An attestation is:
 * - a string fully identifying the attestation type
 * - a type for public parameters
 * - a type for private parameters
 * - a type for data (which is left generic when defining attestation types)
 * - a function `verify(publicInput: Public, privateInput: Private, data: Data)` that asserts the attestation is valid
 */
type Attestation<Id extends string, Public, Private, Data> = {
  type: 'attestation';
  id: Id;
  public: ProvablePureType<Public>;
  private: ProvableType<Private>;
  data: NestedProvablePureFor<Data>;

  verify(publicInput: Public, privateInput: Private, data: Data): void;
};

function defineAttestation<
  Id extends string,
  PublicType extends ProvablePureType,
  PrivateType extends ProvableType
>(config: {
  id: Id;
  public: PublicType;
  private: PrivateType;

  verify<DataType extends NestedProvablePure>(
    publicInput: InferProvableType<PublicType>,
    privateInput: InferProvableType<PrivateType>,
    dataType: DataType,
    data: InferNestedProvable<DataType>
  ): void;
}) {
  return function attestation<DataType extends NestedProvablePure>(
    dataType: DataType
  ): Attestation<
    Id,
    InferProvableType<PublicType>,
    InferProvableType<PrivateType>,
    InferNestedProvable<DataType>
  > {
    return {
      type: 'attestation',
      id: config.id,
      public: config.public,
      private: config.private,
      data: dataType as any,
      verify(publicInput, privateInput, data) {
        return config.verify(publicInput, privateInput, dataType, data);
      },
    };
  };
}

// dummy attestation with no proof attached
const ANone = defineAttestation({
  id: 'none',
  public: Undefined_,
  private: Undefined_,
  verify() {
    // do nothing
  },
});

// native signature
const ASignature = defineAttestation({
  id: 'native-signature',
  public: PublicKey, // issuer public key
  private: Signature,

  // verify the signature
  verify(issuerPk, signature, type, data) {
    let ok = signature.verify(
      issuerPk,
      NestedProvable.get(type).toFields(data)
    );
    assert(ok, 'Invalid signature');
  },
});

// TODO recursive proof
const AProof = defineAttestation({
  id: 'proof',
  // TODO include hash of public inputs of the inner proof
  // TODO maybe names could be issuer, credential
  public: Field, // the verification key hash (TODO: make this a `VerificationKey` when o1js supports it)
  private: Struct({
    vk: VerificationKey, // the verification key
    proof: Undefined_, // the proof, TODO: make this a `DynamicProof` when o1js supports it, or by refactoring our provable type representation
  }),

  verify(vkHash, { vk, proof }, _type, data) {
    vk.hash.assertEquals(vkHash);
    // proof.verify(vk);
    // TODO we also need to somehow ensure that the proof's output type matches the data type
    // proof.publicOutput.assertEquals(data);
    throw Error('Proof attestation not implemented');
  },
});

const Attestation = {
  none: ANone,
  proof: AProof,
  signature: ASignature,
};

const Input = {
  public: publicParameter,
  private: privateParameter,
  constant,
};

const Operation = {
  property,
  equals,
  and,
};

type Constant<Data> = {
  type: 'constant';
  data: ProvableType<Data>;
  value: Data;
};
type Public<Data> = { type: 'public'; data: NestedProvablePureFor<Data> };
type Private<Data> = { type: 'private'; data: NestedProvableFor<Data> };

type Input<Data = any> =
  | Attestation<string, any, any, Data>
  | Constant<Data>
  | Public<Data>
  | Private<Data>;

type Node<Data = any> =
  | { type: 'constant'; data: Data }
  | { type: 'root'; input: Record<string, Input> }
  | { type: 'property'; key: string; inner: Node }
  | { type: 'equals'; left: Node; right: Node }
  | { type: 'and'; left: Node<Bool>; right: Node<Bool> };

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
    case 'and': {
      let left = evalNode(root, node.left);
      let right = evalNode(root, node.right);
      return left.and(right) as Data;
    }
  }
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
    case 'and': {
      return Bool as any;
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

function and(left: Node<Bool>, right: Node<Bool>): Node<Bool> {
  return { type: 'and', left, right };
}

// TODO remove
// small inline test

const isMain = import.meta.filename === process.argv[1];
if (isMain) {
  const Bytes32 = Bytes(32);
  const InputData = { age: Field, name: Bytes32 };

  const spec = Spec(
    {
      signedData: Attestation.signature(InputData),
      targetAge: Input.public(Field),
      targetName: Input.constant(Bytes32, Bytes32.fromString('Alice')),
    },
    ({ signedData, targetAge, targetName }) => ({
      assert: Operation.and(
        Operation.equals(Operation.property(signedData, 'age'), targetAge),
        Operation.equals(Operation.property(signedData, 'name'), targetName)
      ),
      data: Operation.property(signedData, 'age'),
    })
  );
  console.log(spec.logic);

  // create user inputs
  let data = { age: Field(18), name: Bytes32.fromString('Alice') };
  let signedData = createAttestation(InputData, data);

  let userInputs: UserInputs<typeof spec.inputs> = {
    signedData,
    targetAge: Field(18),
  };

  // evaluate the logic at input
  let { privateInput, publicInput } = splitUserInputs(spec, userInputs);
  let root = recombineDataInputs(spec, publicInput, privateInput);
  let assert = Node.eval(root, spec.logic.assert);
  let output = Node.eval(root, spec.logic.data);
  Provable.log({ publicInput, privateInput, root, assert, output });

  // public inputs, extracted at the type level
  type specPublicInputs = PublicInputs<typeof spec.inputs>;

  // private inputs, extracted at the type level
  type specPrivateInputs = PrivateInputs<typeof spec.inputs>;

  function createAttestation<Data>(type: NestedProvableFor<Data>, data: Data) {
    let issuer = PrivateKey.randomKeypair();
    let signature = Signature.create(
      issuer.privateKey,
      NestedProvable.get(type).toFields(data)
    );
    return { public: issuer.publicKey, private: signature, data };
  }
}

function publicInputTypes<S extends Spec>({
  inputs,
}: S): Record<string, NestedProvablePure> {
  let result: Record<string, NestedProvablePure> = {};

  Object.entries(inputs).forEach(([key, input]) => {
    if (input.type === 'attestation') {
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
    if (input.type === 'attestation') {
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
    if (input.type === 'attestation') {
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

function verifyAttestations<S extends Spec>(
  spec: S,
  publicInputs: Record<string, any>,
  privateInputs: Record<string, any>
) {
  Object.entries(spec.inputs).forEach(([key, input]) => {
    if (input.type === 'attestation') {
      let publicInput = publicInputs[key];
      let { private: privateInput, data } = privateInputs[key];
      console.log('verifying', key, input.id);
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
    if (input.type === 'attestation') {
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

type ToPublic<T extends Input> = T extends Attestation<
  string,
  infer Public,
  any,
  any
>
  ? Public
  : T extends Public<infer Data>
  ? Data
  : never;

type ToPrivate<T extends Input> = T extends Attestation<
  string,
  any,
  infer Private,
  infer Data
>
  ? { private: Private; data: Data }
  : T extends Private<infer Data>
  ? Data
  : never;

type ToUserInput<T extends Input> = T extends Attestation<
  string,
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
