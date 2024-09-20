import {
  Field,
  PublicKey,
  Poseidon,
  Struct,
  ZkProgram,
  Proof,
  VerificationKey,
  ProofBase,
  verify,
  ProvablePure,
} from 'o1js';
import { createProgram } from './program.js';
import { AttestationType } from './types.js';

export { Credential };

class Credential<PublicOutput extends Record<string, any>> {
  private constructor(
    public zkProgram: ReturnType<typeof ZkProgram>,
    public vk: VerificationKey
  ) {}

  static async create<PublicInput extends Record<string, any>>(
    attestationType: AttestationType<PublicInput>
  ): Promise<Credential<PublicInput>> {
    const program = createProgram(attestationType);
    const vk = (await program.compile()).verificationKey;

    return new Credential(program, vk);
  }

  async verify(proof: ProofBase<any, any>): Promise<boolean> {
    const proofIsValid = verify(proof, this.vk);

    if (!proofIsValid) {
      console.log('Proof verification failed');
      return false;
    }

    return true;
  }

  async prove<PublicParams extends Record<string, any>>(
    publicParams: PublicParams
  ): Promise<Proof<PublicKey, ProvablePure<PublicParams>>> {
    return this.zkProgram.verify(publicParams);
  }
}
