import { Proof, PublicKey, VerificationKey } from "o1js";

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

// TODO: One compelling idea is to standardize attestations around the universal interface of recursive proofs: 
// an attestation could be modeled as:
// public input:
//  - the attested data (arbitrary type)
//  - public key of the owner
// proof + verification key
interface LocalCredentialParams {
    claims: { [key: string]: any }; // Claims about the subject
}

interface Attestation<PublicInput, PublicOutput> {
    publicInput: {
        data: any;
        publicKey: PublicKey;
    };
    proof: Proof<PublicInput, PublicOutput>;
    vk: VerificationKey;
}

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
    prove(claimKey: string, publicParams: object, credentialVerificationInstance: CredentialVerificationInstance): Promise<ProofResponse>;
}

interface ProofResponse {
    proof: object;
    proofId: string;
    valid: boolean;
    publicParams: object;
}

// TODO: In the original RFC (https://github.com/MinaFoundation/Core-Grants/blob/attestation-api/RFCs/rfc-0009-wallet-attestation-api.md) 
// they provided another interface for the CredentialVerificationInstance
// the name and input fields are the same but for logic they previously used OperationNode and for output they used only bool. 
// Which ones should we go with?
interface CredentialVerificationInstance {
    name: string;
    input: { [key: string]: 'number' | 'string' | 'boolean' };
    output: { [key: string]: 'number' | 'string' | 'boolean' };
    logic: (input: { [key: string]: any }) => { [key: string]: any };
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