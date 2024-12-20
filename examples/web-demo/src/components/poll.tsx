import React, { useState } from 'react';
import { Label } from './ui/label';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { submitVote } from '../interactions/presentation-request';
import { useToast } from './ui/toast';

type PollResults = {
  btc: number;
  eth: number;
};

const AnonymousPoll: React.FC<{ useMockWallet: boolean }> = ({
  useMockWallet,
}) => {
  const [selectedOption, setSelectedOption] = useState<'btc' | 'eth' | null>(
    null
  );
  const [isLoading, setIsLoading] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<PollResults | null>(null);
  const { toast } = useToast();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedOption) return;

    setError(null);

    try {
      const { btc, eth, voteCounted, failureReason } = await submitVote(
        selectedOption,
        useMockWallet,
        setIsLoading
      );
      setResults({ btc, eth });
      if (!voteCounted) setError(failureReason);
      else {
        // show success toast
        toast({
          title: 'Success',
          description: 'Vote submitted',
          className: 'bg-green-50 border border-green-200 text-green-800',
        });
      }
    } catch (err) {
      console.error(err);
      setError(err instanceof Error ? err.message : 'Failed to submit vote');
    } finally {
      setIsLoading(undefined);
    }
  };

  // Transform results for recharts
  const chartData = results
    ? [
        { name: 'Bitcoin', votes: results.btc },
        { name: 'Ethereum', votes: results.eth },
      ]
    : [];

  return (
    <div className="bg-white p-6 rounded-lg shadow-sm space-y-6">
      <h2 className="text-xl font-semibold text-gray-900">
        Bitcoin or Ethereum?
      </h2>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-md">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <div className="flex items-center space-x-2">
            <input
              type="radio"
              id="btc"
              name="vote"
              value="btc"
              className="w-4 h-4"
              onChange={() => setSelectedOption('btc')}
              checked={selectedOption === 'btc'}
            />
            <Label htmlFor="btc">Bitcoin</Label>
          </div>

          <div className="flex items-center space-x-2">
            <input
              type="radio"
              id="eth"
              name="vote"
              value="eth"
              className="w-4 h-4"
              onChange={() => setSelectedOption('eth')}
              checked={selectedOption === 'eth'}
            />
            <Label htmlFor="eth">Ethereum</Label>
          </div>
        </div>

        <p className="text-sm text-gray-500 italic">
          Only non-US citizens over 18 are allowed to vote
        </p>

        <button
          type="submit"
          disabled={!!isLoading || !selectedOption}
          className="w-full p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isLoading ?? 'Submit vote'}
        </button>
      </form>

      {results && (
        <div className="space-y-6 pt-6 border-t">
          <h3 className="font-medium text-gray-900">Current Results</h3>

          {/* Chart */}
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="votes" fill="#2563eb" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Progress bars */}
          <div className="space-y-2">
            <div className="space-y-1">
              <div className="flex justify-between text-sm">
                <span>Bitcoin</span>
                <span>{results.btc} votes</span>
              </div>
              <div className="w-full bg-gray-100 rounded-full h-2">
                <div
                  className="bg-blue-600 h-2 rounded-full"
                  style={{
                    width: `${
                      (results.btc / (results.btc + results.eth)) * 100
                    }%`,
                  }}
                />
              </div>
            </div>

            <div className="space-y-1">
              <div className="flex justify-between text-sm">
                <span>Ethereum</span>
                <span>{results.eth} votes</span>
              </div>
              <div className="w-full bg-gray-100 rounded-full h-2">
                <div
                  className="bg-blue-600 h-2 rounded-full"
                  style={{
                    width: `${
                      (results.eth / (results.btc + results.eth)) * 100
                    }%`,
                  }}
                />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AnonymousPoll;
