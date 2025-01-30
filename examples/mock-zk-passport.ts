import {
  Credential,
  DynamicString,
  PresentationRequest,
  Spec,
} from 'mina-attestations';
import { owner, ownerKey } from '../tests/test-utils.ts';

const String = DynamicString({ maxLength: 30 });

let passportCredentialSpec = await Credential.Recursive.fromMethod(
  {
    name: 'passport',
    public: { nationality: String },
    data: { nationality: String },
  },
  async () => {
    return { nationality: String.from('Austria') };
  }
);
passportCredentialSpec.create({
  owner,
  privateInput: undefined,
  publicInput: undefined,
});

let spec = Spec(
  {
    passport: passportCredentialSpec,
  },
  ({ passport }) => ({})
);
