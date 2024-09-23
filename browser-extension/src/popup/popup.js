document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('attestationForm');
  const generateProofButton = document.getElementById('generateProof');

  // Load saved values
  chrome.storage.sync.get(['age', 'signature', 'issuerPublicKey'], (result) => {
    document.getElementById('age').value = result.age || '';
    document.getElementById('signature').value = result.signature || '';
    document.getElementById('issuerPublicKey').value =
      result.issuerPublicKey || '';
  });

  // Save form data
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const age = document.getElementById('age').value;
    const signature = document.getElementById('signature').value;
    const issuerPublicKey = document.getElementById('issuerPublicKey').value;

    chrome.storage.sync.set({ age, signature, issuerPublicKey }, () => {
      console.log('Data saved');
    });
  });

  // Open proof generation page
  generateProofButton.addEventListener('click', () => {
    chrome.tabs.create({ url: 'proof/proof.html' });
  });
});
