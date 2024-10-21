import { Field, Proof } from 'o1js';
import {
  Spec,
  type Input,
  type Claims,
  type PublicInputs,
} from './program-spec';

type PresentationRequest<
  Output,
  Inputs extends Record<string, Input>,
  InputContext,
  WalletContext
> = {
  programSpec: Spec<Output, Inputs>;
  claims: Claims<Inputs>;
  inputContext?: InputContext;

  deriveContext(walletContext: WalletContext): Field;
};

type Presentation<Output, Inputs extends Record<string, Input>> = {
  version: 'v0';
  claims: Claims<Inputs>;
  outputClaim: Output;
  proof: Proof<PublicInputs<Inputs>, Output>;
};
