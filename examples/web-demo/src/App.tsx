import React, { useState, useEffect } from 'react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from './components/ui/tabs';
import { Switch } from './components/ui/switch';
import { Label } from './components/ui/label';
import { Copy } from 'lucide-react';
import { getPublicKey, issueCredential } from './interactions/issue-credential';

// Helper function to generate random hex string
const generateHexString = (length: number): string => {
  return Array.from({ length }, () =>
    Math.floor(Math.random() * 16).toString(16)
  ).join('');
};

const CopyableCode: React.FC<{ value: string; label: string }> = ({
  value,
  label,
}) => {
  const copyToClipboard = () => {
    navigator.clipboard.writeText(value);
  };

  return (
    <div className="space-y-2">
      <h2 className="text-xl font-semibold text-gray-900">{label}</h2>
      <div className="relative">
        <pre className="bg-gray-100 p-4 rounded-lg font-mono text-sm whitespace-pre-wrap break-all">
          {value}
        </pre>
        <button
          onClick={copyToClipboard}
          className="absolute top-3 right-3 p-2 hover:bg-gray-200 rounded-md"
          title="Copy to clipboard"
        >
          <Copy size={16} />
        </button>
      </div>
    </div>
  );
};

const IssueCredentialsForm: React.FC<{
  useMockWallet: boolean;
  formData: {
    name: string;
    birthDate: string;
    nationality: string;
    id: string;
    expiresAt: string;
  };
  onFormDataChange: (formData: any) => void;
  onSubmit: () => void;
  onClear: () => void;
}> = ({ useMockWallet, formData, onFormDataChange, onSubmit, onClear }) => {
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit();
  };

  const regenerateId = () => {
    onFormDataChange({ ...formData, id: generateHexString(32) });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="name">Name</Label>
        <input
          id="name"
          type="text"
          required
          className="w-full p-2 border rounded-md"
          value={formData.name}
          onChange={(e) =>
            onFormDataChange({ ...formData, name: e.target.value })
          }
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="birthDate">Birth Date</Label>
        <input
          id="birthDate"
          type="date"
          required
          className="w-full p-2 border rounded-md"
          value={formData.birthDate}
          onChange={(e) =>
            onFormDataChange({ ...formData, birthDate: e.target.value })
          }
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="nationality">Nationality</Label>
        <input
          id="nationality"
          type="text"
          required
          className="w-full p-2 border rounded-md"
          value={formData.nationality}
          onChange={(e) =>
            onFormDataChange({ ...formData, nationality: e.target.value })
          }
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="id">ID</Label>
        <div className="flex space-x-2">
          <input
            id="id"
            type="text"
            required
            className="flex-1 p-2 border rounded-md font-mono text-sm"
            value={formData.id}
            onChange={(e) =>
              onFormDataChange({ ...formData, id: e.target.value })
            }
          />
          <button
            type="button"
            onClick={regenerateId}
            className="px-4 py-2 bg-gray-100 rounded-md hover:bg-gray-200"
          >
            Generate
          </button>
        </div>
      </div>

      <div className="space-y-2">
        <Label htmlFor="expiresAt">Expires At</Label>
        <input
          id="expiresAt"
          type="date"
          required
          className="w-full p-2 border rounded-md"
          value={formData.expiresAt}
          onChange={(e) =>
            onFormDataChange({ ...formData, expiresAt: e.target.value })
          }
        />
      </div>

      <div className="flex space-x-4">
        <button
          type="submit"
          className="flex-1 p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
        >
          Issue Credential
        </button>
        <button
          type="button"
          onClick={(e) => {
            e.preventDefault();
            onClear();
          }}
          className="flex-1 p-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200"
        >
          Clear Form
        </button>
      </div>
    </form>
  );
};

const App: React.FC = () => {
  const [useMockWallet, setUseMockWallet] = useState(true);
  const [publicKey, setPublicKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [issuedCredential, setIssuedCredential] = useState<string | null>(null);

  // Lifted form state
  const [formData, setFormData] = useState({
    name: '',
    birthDate: '',
    nationality: '',
    id: generateHexString(32),
    expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
      .toISOString()
      .split('T')[0],
  });

  const handleClearForm = () => {
    setFormData({
      name: '',
      birthDate: '',
      nationality: '',
      id: generateHexString(32),
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
        .toISOString()
        .split('T')[0],
    });
    setIssuedCredential(null);
    setError(null);
  };

  const handleSubmitForm = async () => {
    try {
      const result = await issueCredential(useMockWallet, {
        ...formData,
        birthDate: new Date(formData.birthDate).getTime(),
        expiresAt: new Date(formData.expiresAt).getTime(),
      });
      setIssuedCredential(result);
      setError(null);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'An error occurred');
      setIssuedCredential(null);
    }
  };

  useEffect(() => {
    const fetchPublicKey = async () => {
      try {
        const key = await getPublicKey(useMockWallet);
        setPublicKey(key);
        setError(null);
      } catch (error) {
        setError(
          error instanceof Error ? error.message : 'Failed to fetch public key'
        );
        setPublicKey(null);
      }
    };

    fetchPublicKey();
  }, [useMockWallet]);

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white border-b border-gray-200">
        <div className="container mx-auto px-4 py-4">
          <div className="flex justify-between items-center">
            <h1 className="text-2xl font-semibold text-gray-900">
              Private Credentials Demo
            </h1>

            <div className="flex items-center space-x-2">
              <Switch
                id="wallet-mode"
                checked={useMockWallet}
                onCheckedChange={setUseMockWallet}
              />
              <Label htmlFor="wallet-mode">
                {useMockWallet ? 'Using mock wallet' : 'Using your wallet'}
              </Label>
            </div>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        <Tabs defaultValue="issue" className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="issue">Issue Credential</TabsTrigger>
            <TabsTrigger value="store">Store Credential</TabsTrigger>
            <TabsTrigger value="verify">Verification Request</TabsTrigger>
          </TabsList>

          <TabsContent value="issue" className="mt-6">
            <div className="bg-white p-6 rounded-lg shadow-sm divide-y divide-gray-200">
              {error && (
                <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-md mb-6">
                  {error}
                </div>
              )}

              <div className="pb-6">
                {publicKey && (
                  <CopyableCode value={publicKey} label="Your public key" />
                )}
              </div>

              <div className="pt-6">
                <h2 className="text-xl font-semibold text-gray-900 mb-6">
                  Enter credential data
                </h2>
                <IssueCredentialsForm
                  useMockWallet={useMockWallet}
                  formData={formData}
                  onFormDataChange={setFormData}
                  onSubmit={handleSubmitForm}
                  onClear={handleClearForm}
                />

                {issuedCredential && (
                  <div className="mt-6">
                    <CopyableCode
                      value={issuedCredential}
                      label="Issued Credential"
                    />
                  </div>
                )}
              </div>
            </div>
          </TabsContent>

          <TabsContent value="store" className="mt-6">
            <div className="bg-white p-6 rounded-lg shadow-sm">
              <h2 className="text-xl font-medium text-gray-900 mb-4">
                Store Credential
              </h2>
              <p className="text-gray-500">
                Store credential content will go here
              </p>
            </div>
          </TabsContent>

          <TabsContent value="verify" className="mt-6">
            <div className="bg-white p-6 rounded-lg shadow-sm">
              <h2 className="text-xl font-medium text-gray-900 mb-4">
                Verification Request
              </h2>
              <p className="text-gray-500">
                Verification request content will go here
              </p>
            </div>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default App;
