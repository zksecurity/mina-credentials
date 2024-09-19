import { Proof, PublicKey, Signature, VerificationKey } from 'o1js';

// TODO: change from interface to type

// ****** EXAMPLE WALLET PROVIDER ATTESTATION API ******

interface MinaWallet {
  attestation: AttestationAPI;
}

interface AttestationAPI {
  initialize(config: AttestationConfig): Promise<void>;
}

interface AttestationConfig {
  apiKey: string;
  endpoint: string;
}

// ****** CREDENTIAL CREATION API ******

interface AttestationAPI {
  create(params: LocalCredentialParams): Promise<CredentialResponse>;
}

interface LocalCredentialParams {
  claims: { [key: string]: any }; // Claims about the subject
}

type Attestation<PublicInput extends Record<string, any>> =
  | {
      publicInput: { data: PublicInput; publicKey: PublicKey; };
      type: 'proof';
      proof: string;
      vk: VerificationKey;
    }
  | {
      publicInput: { data: PublicInput; publicKey: PublicKey; };
      type: 'signature';
      signature: string;
      issuerPubKey: string;
      signatureScheme: string; // TODO: later can be an enum
    };

interface CredentialResponse {
  credentialId: string;
  credential: string; // Encoded credential
  nullifier?: string; // Unique identifier for the credential
  nullifierKey?: string; // Key associated with the nullifier
  nullifierProof?: string; // Proof that the nullifierKey was derived as expected
  expiration?: number; // Expiration time if set
}

// ****** CREDENTIALPROGRAM.CREATE API ******

interface CredentialProgramInput {
  [key: string]: 'number' | 'string' | 'boolean';
}

interface CredentialProgramOutput {
  [key: string]: 'boolean';
}

interface CredentialProgramConfig {
  name: string;
  input: CredentialProgramInput;
  output: CredentialProgramOutput;
  logic: OperationNode;
}

interface OperationNode {
  operation: string;
  inputs?: (OperationNode | any)[]; // The inputs can be either another operation node or a static value
  [key: string]: any; // Allow for additional properties specific to the operation
}

interface CredentialProgram {
  create(config: CredentialProgramConfig): CredentialVerificationInstance;
}

interface CredentialVerificationInstance {
  name: string;
  input: CredentialProgramInput;
  output: CredentialProgramOutput;
  logic: OperationNode;
}

// TODO: decide credentialProgram.Operations API

// ****** CREDENTIAL.CREATE API ******

interface CredentialAPI {
  create(claims: string): Credential;
}

interface Credential {
  claims: { [key: string]: any };
  issuerPublicKey: string;
  signature: string;
}

// ****** CREDENTIAL.PROVE API ******

interface ProofAPI {
  prove(
    claimKey: string,
    publicParams: object,
    credentialVerificationInstance: CredentialVerificationInstance
  ): Promise<ProofResponse>;
}

interface ProofResponse {
  proof: object;
  proofId: string;
  valid: boolean;
  publicParams: object;
}

// ****** PROOF COMPOSITION API ******

interface AttestationAPI {
  composeAttestation(params: ComposeParams): Promise<ComposeResponse>;
}

interface ComposeParams {
  attestationIds: string[]; // List of attestation IDs to be composed
}

interface ComposeResponse {
  compositeAttestationId: string;
  compositeProof: string; // Composite cryptographic proof
}
