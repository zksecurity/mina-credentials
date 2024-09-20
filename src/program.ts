import { ZkProgram, PublicKey, Signature, Proof, Field } from 'o1js';
import type { AttestationType } from './program-config.ts';

export { createProgram };

type Program<PublicInput, PublicOutput> = {
  compile(): Promise<{ verificationKey: { data: string; hash: Field } }>;
  // TODO
  run(input: PublicInput, ...args: any): Promise<Proof<any, PublicOutput>>;
};

function createProgram<PublicOutput extends Record<string, any>>(
  attestation: AttestationType<PublicOutput>
): Program<PublicKey, PublicOutput> {
  switch (attestation.type) {
    case 'proof':
      throw new Error('Proof attestation not supported');
    case 'signature':
      return ZkProgram({
        name: 'signature-program',
        publicInput: PublicKey,
        publicOutput: attestation.provableType,
        methods: {
          run: {
            privateInputs: [attestation.provableType, Signature],
            async method(
              issuerPublicKey: PublicKey,
              input: PublicOutput,
              signature: Signature
            ): Promise<PublicOutput> {
              signature.verify(
                issuerPublicKey,
                attestation.provableType.toFields(input)
              );
              return input;
            },
          },
        },
      });
    case 'none':
      return ZkProgram({
        name: 'none-program',
        publicInput: PublicKey,
        publicOutput: attestation.provableType,
        methods: {
          run: {
            privateInputs: [attestation.provableType],
            async method(
              publicKey: PublicKey,
              input: PublicOutput
            ): Promise<PublicOutput> {
              return input;
            },
          },
        },
      });
  }
}
