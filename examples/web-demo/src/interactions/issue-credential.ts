export { getPublicKey, issueCredential };

async function getPublicKey(useMockWallet: boolean): Promise<string> {
  return 'not implemented';
}

type DataInput = {
  name: string;
  birthDate: number;
  nationality: string;
  /**
   * Hex string of length 32
   */
  id: string;
  expiresAt: number;
};

async function issueCredential(
  useMockWallet: boolean,
  data: DataInput
): Promise<string> {
  // Simulate network delay
  await new Promise((resolve) => setTimeout(resolve, 1000));

  // Validate the data
  if (
    !data.name ||
    !data.birthDate ||
    !data.nationality ||
    !data.id ||
    !data.expiresAt
  ) {
    throw new Error('All fields are required');
  }

  // Return a mock credential
  return (
    'cred.eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.MKW_zZZhnlkz9bmV6einho4qGH_i7QaMW-xdzP3ExdXnZKhRJ3' +
    JSON.stringify(data)
  );
}
