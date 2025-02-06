import React from 'react';
import { Copy } from 'lucide-react';

export { CopyableCode };

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
