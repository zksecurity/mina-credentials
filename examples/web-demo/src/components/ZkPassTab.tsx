import React, { useState } from 'react';
import { Label } from './ui/label';
import TransgateConnect from '@zkpass/transgate-js-sdk';

interface Result {
  allocatorAddress: string;
  allocatorSignature: string;
  publicFields: any[];
  publicFieldsHash: string;
  taskId: string;
  uHash: string;
  validatorAddress: string;
  validatorSignature: string;
  recipient?: string;
}

const ZkPassTab: React.FC = () => {
  const [appId, setAppId] = useState<string>(
    'd15ae509-2b52-4286-920b-41b011b8285c'
  );
  const [schemaId, setSchemaId] = useState<string>(
    '3ec11dea72464d729f76a7d42b7e98b8'
  );
  const [result, setResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const start = async () => {
    try {
      setError(null);
      setIsLoading(true);

      console.log('Creating connector...');
      const connector = new TransgateConnect(appId);
      console.log('Connector created:', connector);

      console.log('Checking TransGate availability...');
      const isAvailable = await connector.isTransgateAvailable();
      console.log('TransGate available:', isAvailable);

      if (!isAvailable) {
        throw new Error('Please install zkPass TransGate');
      }

      console.log('Launching schema with ID:', schemaId);
      try {
        const res = await connector.launch(schemaId);
        console.log('Launch response:', res);
        setResult(res);
      } catch (launchError) {
        console.error('Launch error:', launchError);
        if (launchError && typeof launchError === 'object') {
          console.error('Launch error details:', {
            name: (launchError as any).name,
            message: (launchError as any).message,
            code: (launchError as any).code,
          });
        }
        throw launchError;
      }
    } catch (err) {
      console.error('Full error object:', err);
      if (err && typeof err === 'object') {
        setError(`Error: ${(err as any).message || 'Unknown error'}`);
      } else {
        setError('An unknown error occurred');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-sm space-y-6">
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-md">
          {error}
        </div>
      )}

      <div className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="appId">App ID:</Label>
          <input
            id="appId"
            type="text"
            className="w-full p-2 border rounded-md font-mono text-sm"
            value={appId}
            onChange={(e) => setAppId(e.target.value)}
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="schemaId">Schema ID:</Label>
          <input
            id="schemaId"
            type="text"
            className="w-full p-2 border rounded-md font-mono text-sm"
            value={schemaId}
            onChange={(e) => setSchemaId(e.target.value)}
          />
        </div>

        <button
          onClick={start}
          disabled={isLoading}
          className="w-full p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isLoading ? 'Processing...' : 'Start Single Schema'}
        </button>
      </div>

      {result && (
        <div className="mt-6 space-y-4">
          <h3 className="text-lg font-semibold">Result:</h3>
          <pre className="bg-gray-100 p-4 rounded-lg overflow-auto max-h-96 text-sm">
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};

export default ZkPassTab;
