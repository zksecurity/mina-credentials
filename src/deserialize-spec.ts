import {
  Field,
  Bool,
  UInt8,
  UInt32,
  UInt64,
  PublicKey,
  Signature,
  Struct,
  Poseidon,
  Provable,
} from 'o1js';
import { Input, Node, Spec, Attestation } from './program-config.ts';
import { NestedProvable } from './nested.ts';

export { deserializeSpec };

function deserializeSpec(serializedSpec: string): Spec {
  const parsedSpec = JSON.parse(serializedSpec);
  return {
    inputs: deserializeInputs(parsedSpec.inputs),
    logic: {
      assert: deserializeNode(parsedSpec.logic.assert),
      data: deserializeNode(parsedSpec.logic.data),
    },
  };
}

function deserializeInputs(
  inputs: Record<string, any>
): Record<string, Input> {}

function deserializeInput(input: any): Input {}

function deserializeNode(node: any): Node {}

function deserializeProvableType(type: { type: string }): Provable<any> {}

function deserializeProvable(type: string, value: string): Provable<any> {}

function deserializeNestedProvableFor(type: any): NestedProvable {}
