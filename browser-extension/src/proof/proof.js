document.addEventListener('DOMContentLoaded', () => {
  const minAgeInput = document.getElementById('minAge');
  const generateProofBtn = document.getElementById('generateProofBtn');
  const proofResultDiv = document.getElementById('proofResult');

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

      // Prepare data for ZK proof generation
      const inputData = {
        storedAge: parseInt(storedData.age, 10),
        minAge: minAge,
        signature: storedData.signature,
        issuerPublicKey: storedData.issuerPublicKey,
      };

      // TODO: Implement actual ZK proof generation here
      // For now, we'll just log the input data and display a placeholder message
      console.log('Input data for ZK proof:', inputData);

      // Placeholder for ZK proof generation
      const isAgeValid = inputData.storedAge >= inputData.minAge;
      const proofMessage = isAgeValid
        ? `Proof generated successfully. The stored age is at least ${minAge}.`
        : `Proof generation failed. The stored age is less than ${minAge}.`;

      proofResultDiv.textContent = proofMessage;
    } catch (error) {
      console.error('Error generating proof:', error);
      proofResultDiv.textContent =
        'An error occurred while generating the proof.';
    }
  });
});
