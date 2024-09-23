import { ZkProgram, PublicKey, Signature } from 'o1js';
import { AttestationType } from './types.js';

export { createProgram };

function createProgram<PublicOutput extends Record<string, any>>(
  attestation: AttestationType<PublicOutput>
) {
  switch (attestation.type) {
    case 'proof':
      throw new Error('Proof attestation not supported');
    case 'signature':
      return ZkProgram({
        name: 'signature-program',
        publicInput: PublicKey,
        publicOutput: attestation.provableType,
        methods: {
          verify: {
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
          verify: {
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
