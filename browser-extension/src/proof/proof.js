document.addEventListener('DOMContentLoaded', async () => {
  console.log('DOMContentLoaded event fired');

  const minAgeInput = document.getElementById('minAge');
  const generateProofBtn = document.getElementById('generateProofBtn');
  const proofResultDiv = document.getElementById('proofResult');
  const sandboxFrame = document.getElementById('sandboxFrame');

  console.log('DOM elements retrieved:', {
    minAgeInput,
    generateProofBtn,
    proofResultDiv,
    sandboxFrame,
  });

  console.log('coop:', self.crossOriginIsolated);

  proofResultDiv.textContent = 'Waiting for sandbox to load...';

  sandboxFrame.addEventListener('load', () => {
    console.log('Sandbox iframe loaded, sending compile message');
    proofResultDiv.textContent = 'Compiling ZK program...';

    sandboxFrame.contentWindow.postMessage({ type: 'compile' }, '*');
  });

  generateProofBtn.addEventListener('click', async () => {
    console.log('Generate Proof button clicked');
    const minAge = parseInt(minAgeInput.value, 10);

    if (isNaN(minAge) || minAge < 0) {
      proofResultDiv.textContent = 'Please enter a valid minimum age.';
      return;
    }

    try {
      console.log('Retrieving stored data from chrome.storage.sync');
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

      console.log('Retrieved age:', storedData.age);
      console.log('Retrieved signature:', storedData.signature);
      console.log('Retrieved issuerPublicKey:', storedData.issuerPublicKey);

      const data = {
        age: storedData.age,
        minAge: minAge,
        signature: storedData.signature,
        issuerPublicKey: storedData.issuerPublicKey,
      };

      console.log('Sending generateProof message to sandbox');
      sandboxFrame.contentWindow.postMessage(
        {
          type: 'generateProof',
          data: data,
        },
        '*'
      );
    } catch (error) {
      console.error('Error retrieving or processing data:', error);
      proofResultDiv.textContent =
        'An error occurred while retrieving the data. Please check the console for details.';
    }
  });

  window.addEventListener('message', (event) => {
    if (event.data.type === 'compilationResult') {
      if (event.data.success) {
        proofResultDiv.textContent =
          'ZK program compiled successfully. Ready to generate proofs.';
      } else {
        proofResultDiv.textContent =
          'Error compiling ZK program. Please check the console for details.';
      }
    } else if (event.data.type === 'proofResult') {
      proofResultDiv.textContent = event.data.result;
    }
  });
});
