import {
  Field,
  PublicKey,
  Poseidon,
  Struct,
  ZkProgram,
  Proof,
  VerificationKey,
} from 'o1js';
import { createProgram } from './program.js';
import { AttestationType } from './types.js';

export { Credential };

class Credential<PublicOutput extends Record<string, any>> {
  private constructor(
    public zkProgram: ReturnType<typeof ZkProgram>,
    public vk: VerificationKey
  ) {}

  proof: Proof<>;

  static async create<PublicInput extends Record<string, any>>(
    attestationType: AttestationType<PublicInput>
  ): Promise<Credential<PublicInput>> {
    const program = createProgram(attestationType);
    const vk = (await program.compile()).verificationKey;

    return new Credential(program, vk);
  }

  async verify(): Promise<boolean> {
    const proofIsValid = await this.zkProgram.verify(this.proof);

    if (!proofIsValid) {
      console.log('Proof verification failed');
      return false;
    }

    return true;
  }
}
