import { Field, PublicKey, Signature, ZkProgram } from 'o1js';

console.log('sandbox.js loaded');

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
    await zkProgram.compile();
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
    const { age, minAgeField, signature, issuerPublicKey } = event.data.data;
    console.log('Proof generation data:', {
      age,
      minAgeField,
      signature,
      issuerPublicKey,
    });

    try {
      if (!compiledZkProgram) {
        throw new Error('ZkProgram not compiled yet');
      }

      console.log('Generating proof');
      const proof = await zkProgram.verifyAge(
        minAgeField,
        age,
        issuerPublicKey,
        signature
      );

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
