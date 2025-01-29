import {
  Credential,
  DynamicString,
  PresentationRequest,
  Spec,
} from 'mina-attestations';
import { PublicKey, Struct, ZkProgram } from 'o1js';

const String = DynamicString({ maxLength: 30 });

class Output extends Struct({
  owner: PublicKey,
  data: { nationality: String },
}) {}

let passportProgram = ZkProgram({
  name: 'passport',
  publicOutput: Output,
  methods: {
    run: {
      privateInputs: [],
      async method() {
        return {
          publicOutput: {
            owner: PublicKey.empty(),
            data: { nationality: String.from('test') },
          },
        };
      },
    },
  },
});

let passportCredential = await Credential.Recursive.fromProgram(
  passportProgram
);

passportCredential.create();

let spec = Spec(
  {
    passport: passportCredential,
  },
  ({ passport }) => ({})
);
