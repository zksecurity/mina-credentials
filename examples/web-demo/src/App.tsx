import React, { useState } from 'react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from './components/ui/tabs';
import { Switch } from './components/ui/switch';
import { Label } from './components/ui/label';

const App: React.FC = () => {
  const [useMockWallet, setUseMockWallet] = useState(true);

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
            <div className="bg-white p-6 rounded-lg shadow-sm">
              <h2 className="text-xl font-medium text-gray-900 mb-4">
                Issue Credential
              </h2>
              <p className="text-gray-500">
                Issue credential content will go here
              </p>
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
