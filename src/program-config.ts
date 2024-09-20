import { PublicKey, VerificationKey, type ProvablePure } from 'o1js';

export type { AttestationType };

type AttestationCommon<PublicInput extends Record<string, any>> = {
  provableType: ProvablePure<PublicInput>;
};

type AttestationType<
  PublicInput extends Record<string, any> = Record<string, any>
> = AttestationCommon<PublicInput> &
  (
    | {
        type: 'proof';
        vk: VerificationKey;
      }
    | {
        type: 'signature';
        issuerPubKey: PublicKey;
        signatureScheme: string; // TODO: later can be an enum
      }
    | {
        type: 'none';
      }
  );
