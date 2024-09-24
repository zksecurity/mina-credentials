import { Field, PublicKey, Signature, ZkProgram } from 'o1js';
import { zkProgram } from '../../src/program.js';

let compiledZkProgram;

document.addEventListener('DOMContentLoaded', async () => {
  const minAgeInput = document.getElementById('minAge');
  const generateProofBtn = document.getElementById('generateProofBtn');
  const proofResultDiv = document.getElementById('proofResult');

  proofResultDiv.textContent = 'Compiling ZK program...';
  try {
    compiledZkProgram = await zkProgram.compile();
    proofResultDiv.textContent =
      'ZK program compiled successfully. Ready to generate proofs.';
  } catch (error) {
    console.error('Error compiling ZK program:', error);
    proofResultDiv.textContent =
      'Error compiling ZK program. Please check the console for details.';
    return;
  }

  generateProofBtn.addEventListener('click', async () => {
    const minAge = parseInt(minAgeInput.value, 10);
    if (isNaN(minAge) || minAge < 0) {
      proofResultDiv.textContent = 'Please enter a valid minimum age.';
      return;
    }

    try {
      // Retrieve stored data
      const storedData = await new Promise((resolve) => {
        chrome.storage.sync.get(
          ['age', 'signature', 'issuerPublicKey'],
          resolve
        );
      });

      if (
        !storedData.age ||
        !storedData.signature ||
        !storedData.issuerPublicKey
      ) {
        proofResultDiv.textContent =
          'Missing required data. Please fill in all fields in the popup.';
        return;
      }

      // Convert stored data to appropriate types
      const age = Field(storedData.age);
      const minAgeField = Field(minAge);
      const signature = Signature.fromJSON(storedData.signature);
      const issuerPublicKey = PublicKey.fromJSON(storedData.issuerPublicKey);

      proofResultDiv.textContent = 'Generating proof...';

      // Generate the proof
      const proof = await zkProgram.verifyAge(
        minAgeField,
        age,
        issuerPublicKey,
        signature
      );

      proofResultDiv.textContent = `Proof generated successfully. The stored age (${storedData.age}) is at least ${minAge}.`;

      // You can do something with the proof here, like sending it to a server or displaying it
      console.log('Generated proof:', proof.toJSON());
    } catch (error) {
      console.error('Error generating proof:', error);
      proofResultDiv.textContent =
        'An error occurred while generating the proof. Please check the console for details.';
    }
  });
});
