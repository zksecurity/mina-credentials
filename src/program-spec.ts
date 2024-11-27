import {
  Bool,
  Field,
  type ProvablePure,
  Signature,
  PublicKey,
  type InferProvable,
} from 'o1js';
import type { ExcludeFromRecord } from './types.ts';
import { assertPure, ProvableType } from './o1js-missing.ts';
import { assert } from './util.ts';
import {
  type InferNestedProvable,
  NestedProvable,
  type NestedProvableFor,
  type NestedProvablePure,
  type NestedProvablePureFor,
} from './nested.ts';
import {
  type CredentialSpec,
  type CredentialType,
  type Credential,
  type CredentialInputs,
  withOwner,
  type CredentialOutputs,
} from './credential.ts';
import { Node, Operation, root, type GetData } from './operation.ts';

export type {
  PublicInputs,
  UserInputs,
  DataInputs,
  ToCredential,
  Input,
  Claims,
};
export {
  Spec,
  Claim,
  Constant,
  publicInputTypes,
  publicOutputType,
  privateInputTypes,
  splitUserInputs,
  extractCredentialInputs,
  recombineDataInputs,
};

type Spec<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = {
  inputs: Inputs;
  logic: Required<OutputNode<Output>>;
};

/**
 * Specify a ZkProgram that verifies and selectively discloses data
 */
function Spec<Output, Inputs extends Record<string, Input>>(
  inputs: Inputs,
  spec: (inputs: {
    [K in keyof Inputs]: Node<GetData<Inputs[K]>>;
  }) => {
    assert?: Node<Bool>;
    outputClaim: Node<Output>;
  }
): Spec<Output, Inputs>;

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
function Spec<Output, Inputs extends Record<string, Input>>(
  inputs: Inputs,
  spec: (inputs: {
    [K in keyof Inputs]: Node<GetData<Inputs[K]>>;
  }) => OutputNode<Output>
): Spec<Output, Inputs> {
  let rootNode = root(inputs);
  let inputNodes: {
    [K in keyof Inputs]: Node<GetData<Inputs[K]>>;
  } = {} as any;
  // some special keys are used internally and must not be used as input keys
  ['owner'].forEach((key) =>
    assert(!(key in inputs), `"${key}" is reserved, can't be used in inputs`)
  );

  for (let key in inputs) {
    if (inputs[key]!.type === 'credential') {
      let credential = Operation.property(rootNode, key) as any;
      let data = Operation.property(credential, 'data') as any;
      inputNodes[key] = data;
    } else {
      inputNodes[key] = Operation.property(rootNode, key) as any;
    }
  }
  let logic = spec(inputNodes);
  let assertNode = logic.assert ?? Node.constant(Bool(true));
  let outputClaim: Node<Output> =
    logic.outputClaim ?? (Node.constant(undefined) as any);

  return { inputs, logic: { assert: assertNode, outputClaim } };
}

type Constant<Data> = {
  type: 'constant';
  data: ProvableType<Data>;
  value: Data;
};
type Claim<Data> = { type: 'claim'; data: NestedProvablePureFor<Data> };

type Input<Data = any> =
  | CredentialSpec<CredentialType, any, Data>
  | Constant<Data>
  | Claim<Data>;

type OutputNode<Data = any> = {
  assert?: Node<Bool>;
  outputClaim?: Node<Data>;
};

function Constant<DataType extends ProvableType>(
  data: DataType,
  value: InferProvable<DataType>
): Constant<InferProvable<DataType>> {
  return { type: 'constant', data, value };
}

function Claim<DataType extends NestedProvablePure>(
  data: DataType
): Claim<InferNestedProvable<DataType>> {
  return { type: 'claim', data: data as any };
}

// helpers to extract/recombine portions of the spec inputs

function publicInputTypes({ inputs }: Spec): NestedProvablePureFor<{
  context: Field;
  claims: Record<string, any>;
}> {
  let claims: Record<string, NestedProvablePure> = {};

  Object.entries(inputs).forEach(([key, input]) => {
    if (input.type === 'claim') {
      claims[key] = input.data;
    }
  });
  return { context: Field, claims };
}

type CredentialInputType = {
  credential: { owner: PublicKey; data: any };
  witness: any;
};

function privateInputTypes({ inputs }: Spec): NestedProvableFor<{
  ownerSignature: Signature;
  credentials: Record<string, CredentialInputType>;
}> {
  let credentials: Record<string, NestedProvableFor<CredentialInputType>> = {};

  Object.entries(inputs).forEach(([key, input]) => {
    if (input.type === 'credential') {
      credentials[key] = {
        credential: withOwner(input.data),
        witness: input.witness,
      };
    }
  });
  return { ownerSignature: Signature, credentials };
}

function publicOutputType(spec: Spec): ProvablePure<any> {
  let root = dataInputTypes(spec);
  let outputTypeNested = Node.evalType(root, spec.logic.outputClaim);
  let outputType = NestedProvable.get(outputTypeNested);
  assertPure(outputType);
  return outputType;
}

function dataInputTypes({ inputs }: Spec): NestedProvable {
  let result: Record<string, NestedProvable> = {};
  Object.entries(inputs).forEach(([key, input]) => {
    if (input.type === 'credential') {
      result[key] = withOwner(input.data);
    } else {
      result[key] = input.data;
    }
  });
  return result;
}

function splitUserInputs<I extends Spec['inputs']>(
  userInputs: UserInputs<I>
): {
  publicInput: PublicInputs<I>;
  privateInput: PrivateInputs<I>;
};
function splitUserInputs({
  context,
  ownerSignature,
  claims,
  credentials,
}: UserInputs<any>) {
  return {
    publicInput: { context, claims },
    privateInput: { ownerSignature, credentials },
  };
}

function extractCredentialInputs(
  spec: Spec,
  { context }: PublicInputs<any>,
  { ownerSignature, credentials }: PrivateInputs<any>
): CredentialInputs {
  let credentialInputs: CredentialInputs['credentials'] = [];

  Object.entries(spec.inputs).forEach(([key, input]) => {
    if (input.type === 'credential') {
      let value: any = credentials[key];
      credentialInputs.push({
        spec: input,
        credential: value.credential,
        witness: value.witness,
      });
    }
  });

  return { context, ownerSignature, credentials: credentialInputs };
}

function recombineDataInputs<S extends Spec>(
  spec: S,
  publicInputs: PublicInputs<any>,
  privateInputs: PrivateInputs<any>,
  credentialOutputs: CredentialOutputs
): DataInputs<S['inputs']>;
function recombineDataInputs<S extends Spec>(
  spec: S,
  { claims }: PublicInputs<any>,
  { credentials }: PrivateInputs<any>,
  credentialOutputs: CredentialOutputs
): Record<string, any> {
  let result: Record<string, any> = {};

  let i = 0;

  Object.entries(spec.inputs).forEach(([key, input]) => {
    if (input.type === 'credential') {
      result[key] = {
        credential: (credentials[key] as any).credential,
        issuer: credentialOutputs.credentials[i]!.issuer,
      };
      i++;
    }
    if (input.type === 'claim') {
      result[key] = claims[key];
    }
    if (input.type === 'constant') {
      result[key] = input.value;
    }
  });
  result.owner = credentialOutputs.owner;
  return result;
}

type Claims<Inputs extends Record<string, Input>> = ExcludeFromRecord<
  MapToClaims<Inputs>,
  never
>;

type PublicInputs<Inputs extends Record<string, Input>> = {
  context: Field;
  claims: Claims<Inputs>;
};

type Credentials<Inputs extends Record<string, Input>> = ExcludeFromRecord<
  MapToCredentials<Inputs>,
  never
>;

type PrivateInputs<Inputs extends Record<string, Input>> = {
  ownerSignature: Signature;
  credentials: Credentials<Inputs>;
};

type UserInputs<Inputs extends Record<string, Input>> = {
  context: Field;
  ownerSignature: Signature;
  claims: ExcludeFromRecord<MapToClaims<Inputs>, never>;
  credentials: ExcludeFromRecord<MapToCredentials<Inputs>, never>;
};

type DataInputs<Inputs extends Record<string, Input>> = ExcludeFromRecord<
  MapToDataInput<Inputs>,
  never
>;

type MapToClaims<T extends Record<string, Input>> = {
  [K in keyof T]: ToClaim<T[K]>;
};

type MapToCredentials<T extends Record<string, Input>> = {
  [K in keyof T]: ToCredential<T[K]>;
};

type MapToDataInput<T extends Record<string, Input>> = {
  [K in keyof T]: ToDataInput<T[K]>;
};

type ToClaim<T extends Input> = T extends Claim<infer Data> ? Data : never;

type ToCredential<T extends Input> = T extends CredentialSpec<
  CredentialType,
  infer Witness,
  infer Data
>
  ? { credential: Credential<Data>; witness: Witness }
  : never;

type ToDataInput<T extends Input> = T extends CredentialSpec<
  CredentialType,
  any,
  infer Data
>
  ? Credential<Data>
  : T extends Input<infer Data>
  ? Data
  : never;
