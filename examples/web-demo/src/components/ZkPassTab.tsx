import React, { useState } from 'react';
import { Label } from './ui/label';
import TransgateConnect from '@zkpass/transgate-js-sdk';
import type { ZkPassResponseItem } from 'mina-attestations/imported';
import { importZkpassProof } from '../interactions/import-credential';
import { useToast } from './ui/toast';

const ZkPassTab: React.FC<{ useMockWallet: boolean }> = ({ useMockWallet }) => {
  const [appId, setAppId] = useState<string>(
    'd15ae509-2b52-4286-920b-41b011b8285c'
  );
  const [schemaId, setSchemaId] = useState<string>(
    '3ec11dea72464d729f76a7d42b7e98b8'
  );
  // const [result, setResult] = useState<any | null>(null);
  const [result, setResult] = useState<any | null>({
    taskId: '056cf69572204b03b143a06203c635d3',
    publicFields: [],
    allocatorAddress: '0x19a567b3b212a5b35bA0E3B600FbEd5c2eE9083d',
    publicFieldsHash:
      '0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6',
    allocatorSignature:
      '0x200d38da83a2399d1d075a668cbcbc9c345cce315a14a99ba02d0b5be77e29084bb8a8e62d5a3e8fe4f4a3a14fec0a3608bd680e7f371cbf94b1799a9f53e0601c',
    uHash: '0x39c0117954ac203e492e77cdb14033d99e5fa2763465803784a18df5076bb328',
    validatorAddress: '0xb1C4C1E1Cdd5Cf69E27A3A08C8f51145c2E12C6a',
    validatorSignature:
      '0x8b39bbbd8304f1f80b6b92e83adefa95bb89f99e5725ded54ddbb6276abcaa8c0c7697b842dd82f0361fa07cd2c67016f8497464b7645e99a61909283fe023971c',
  });
  // const [schemaIdWithResult, setSchemaIdWithResult] = useState<
  //   string | undefined
  // >(undefined);
  const [schemaIdWithResult, setSchemaIdWithResult] = useState<
    string | undefined
  >('3ec11dea72464d729f76a7d42b7e98b8');

  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<string | undefined>(undefined);
  const [isLoading2, setIsLoading2] = useState<string | undefined>(undefined);
  const { toast } = useToast();

  const start = async () => {
    try {
      setError(null);
      setIsLoading('Processing...');

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
        setSchemaIdWithResult(schemaId);
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
      setIsLoading(undefined);
    }
  };

  async function importCredential(
    schemaId: string,
    result: ZkPassResponseItem
  ) {
    try {
      setIsLoading2('Preparing import...');
      await importZkpassProof(schemaId, result, useMockWallet, setIsLoading2);
      // show success toast
      toast({
        title: 'Success',
        description: 'Credential imported',
        className: 'bg-green-50 border border-green-200 text-green-800',
      });
    } catch (err) {
      console.error(err);
      setError(
        err instanceof Error ? err.message : 'Failed to create credential'
      );
    } finally {
      setIsLoading2(undefined);
    }
  }

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
          disabled={!!isLoading}
          className="w-full p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isLoading ?? 'Start ZkPass Proof'}
        </button>
      </div>

      {result && schemaIdWithResult && (
        <div className="mt-6 space-y-4">
          <h3 className="text-lg font-semibold">Result:</h3>
          <pre className="bg-gray-100 p-4 rounded-lg overflow-auto max-h-96 text-sm">
            {JSON.stringify(result, null, 2)}
          </pre>
          <button
            onClick={() => importCredential(schemaIdWithResult, result)}
            disabled={!!isLoading2}
            className="w-full p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading2 ?? 'Import as Credential'}
          </button>
        </div>
      )}
    </div>
  );
};

export default ZkPassTab;
