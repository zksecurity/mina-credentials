export type { Credential as UnusedCredential };

// ****** EXAMPLE WALLET PROVIDER ATTESTATION API ******

type MinaWallet = {
  attestation: AttestationAPI;
};

type AttestationAPI = {
  initialize(config: AttestationConfig): Promise<void>;
};

type AttestationConfig = {
  apiKey: string;
  endpoint: string;
};

// ****** CREDENTIAL CREATION API ******

type CredentialAttestationAPI = {
  create(params: LocalCredentialParams): Promise<CredentialResponse>;
};

type LocalCredentialParams = {
  claims: { [key: string]: any }; // Claims about the subject
};

type CredentialResponse = {
  credentialId: string;
  credential: string; // Encoded credential
  nullifier?: string; // Unique identifier for the credential
  nullifierKey?: string; // Key associated with the nullifier
  nullifierProof?: string; // Proof that the nullifierKey was derived as expected
  expiration?: number; // Expiration time if set
};

// ****** CREDENTIALPROGRAM.CREATE API ******

type CredentialProgramInput = {
  [key: string]: 'number' | 'string' | 'boolean';
};

type CredentialProgramOutput = {
  [key: string]: 'boolean';
};

type CredentialProgramConfig = {
  name: string;
  input: CredentialProgramInput;
  output: CredentialProgramOutput;
  logic: OperationNode;
};

type OperationNode = {
  operation: string;
  inputs?: (OperationNode | any)[]; // The inputs can be either another operation node or a static value
  [key: string]: any; // Allow for additional properties specific to the operation
};

type CredentialProgram = {
  create(config: CredentialProgramConfig): CredentialVerificationInstance;
};

type CredentialVerificationInstance = {
  name: string;
  input: CredentialProgramInput;
  output: CredentialProgramOutput;
  logic: OperationNode;
};

// TODO: decide credentialProgram.Operations API

// ****** CREDENTIAL.CREATE API ******

type CredentialAPI = {
  create(claims: string): Credential;
};

type Credential = {
  claims: { [key: string]: any };
  issuerPublicKey: string;
  signature: string;
};

// ****** CREDENTIAL.PROVE API ******

type ProofAPI = {
  prove(
    claimKey: string,
    publicParams: object,
    credentialVerificationInstance: CredentialVerificationInstance
  ): Promise<ProofResponse>;
};

type ProofResponse = {
  proof: object;
  proofId: string;
  valid: boolean;
  publicParams: object;
};

// ****** PROOF COMPOSITION API ******

type ProofAttestationAPI = {
  composeAttestation(params: ComposeParams): Promise<ComposeResponse>;
};

type ComposeParams = {
  attestationIds: string[]; // List of attestation IDs to be composed
};

type ComposeResponse = {
  compositeAttestationId: string;
  compositeProof: string; // Composite cryptographic proof
};
