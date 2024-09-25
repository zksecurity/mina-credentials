import { Field, PublicKey, Signature, ZkProgram } from 'o1js';

console.log('sandbox.js loaded');

console.log('sandbox coop: ', self.crossOriginIsolated);

let compiledZkProgram;

console.log('Defining ZkProgram');
const zkProgram = ZkProgram({
  name: 'AgeCheck',
  publicInput: Field,
  publicOutput: PublicKey,
  methods: {
    verifyAge: {
      privateInputs: [Field, PublicKey, Signature],
      async method(minAge, age, issuerPubKey, signature) {
        const validSignature = signature.verify(issuerPubKey, [age]);
        validSignature.assertTrue();
        age.assertGreaterThanOrEqual(minAge);
        return issuerPubKey;
      },
    },
  },
});

async function compileProgram() {
  console.log('Compiling ZkProgram');
  try {
    let { verificationKey } = await zkProgram.compile();
    console.log('Verification Key:', verificationKey);
    compiledZkProgram = true;
    console.log('ZkProgram compiled successfully');
    window.parent.postMessage(
      {
        type: 'compilationResult',
        success: true,
      },
      '*'
    );
  } catch (error) {
    console.error('Error compiling ZK program:', error);
    window.parent.postMessage(
      {
        type: 'compilationResult',
        success: false,
      },
      '*'
    );
  }
}

window.addEventListener('message', async (event) => {
  console.log('Received message in sandbox:', event.data);

  if (event.data.type === 'compile') {
    console.log('Compile message received, starting compilation');
    await compileProgram();
  } else if (event.data.type === 'generateProof') {
    console.log('Generate proof message received');
    const { age, minAge, signature, issuerPublicKey } = event.data.data;
    console.log('Proof generation data:', {
      age,
      minAge,
      signature,
      issuerPublicKey,
    });

    try {
      if (!compiledZkProgram) {
        throw new Error('ZkProgram not compiled yet');
      }

      let minAgeField = Field(minAge);
      let ageField = Field(age);
      let issuerPubKeyPK = PublicKey.fromBase58(issuerPublicKey);
      let signatureSig = Signature.fromBase58(signature);

      console.log('Proof generation data after typing:', {
        ageField,
        minAgeField,
        signatureSig,
        issuerPubKeyPK,
      });

      console.log('Generating proof');
      let proof = await zkProgram.verifyAge(
        minAgeField,
        ageField,
        issuerPubKeyPK,
        signatureSig
      );

      let verification = await zkProgram.verify(proof);
      console.log('Verified proof:', verification);

      console.log('Proof generated successfully');
      window.parent.postMessage(
        {
          type: 'proofResult',
          result: `Proof generated successfully. The stored age (${age.toString()}) is at least ${minAgeField.toString()}.`,
        },
        '*'
      );

      console.log('Generated proof:', proof.toJSON());
    } catch (error) {
      console.error('Error generating proof:', error);
      window.parent.postMessage(
        {
          type: 'proofResult',
          result:
            'An error occurred while generating the proof. Please check the console for details.',
        },
        '*'
      );
    }
  }
});

console.log('sandbox.js event listener set up');
