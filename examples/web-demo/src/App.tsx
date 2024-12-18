import React, { useState } from 'react';
import { Clock, Star, Globe } from 'lucide-react';

// Define interfaces for our components
interface FeatureCardProps {
  icon: React.ReactNode;
  title: string;
  description: string;
}

// Feature Card Component
const FeatureCard: React.FC<FeatureCardProps> = ({
  icon,
  title,
  description,
}) => {
  return (
    <div className="bg-white p-6 rounded-lg shadow-md hover:shadow-xl transition-all duration-300">
      <div className="mb-4 text-blue-600">{icon}</div>
      <h3 className="text-xl font-semibold mb-2">{title}</h3>
      <p className="text-gray-600">{description}</p>
    </div>
  );
};

// Main App Component
const App: React.FC = () => {
  const [count, setCount] = useState(0);

  const incrementCount = () => {
    setCount(count + 1);
  };

  return (
    <div className="min-h-screen bg-gray-100 flex flex-col">
      {/* Header */}
      <header className="bg-blue-600 text-white p-6 text-center">
        <h1 className="text-3xl font-bold">Welcome to My React Demo</h1>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8 flex-grow">
        {/* Counter Section */}
        <section className="mb-8 text-center">
          <h2 className="text-2xl mb-4">Interactive Counter</h2>
          <div className="flex justify-center items-center space-x-4">
            <p className="text-xl font-semibold">Count: {count}</p>
            <button
              onClick={incrementCount}
              className="bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600 transition-colors"
            >
              Increment
            </button>
          </div>
        </section>

        {/* Features Grid */}
        <section>
          <h2 className="text-2xl text-center mb-6">Key Features</h2>
          <div className="grid md:grid-cols-3 gap-6">
            <FeatureCard
              icon={<Clock size={48} />}
              title="Real-Time"
              description="Experience lightning-fast updates with React's efficient rendering."
            />
            <FeatureCard
              icon={<Star size={48} />}
              title="Modern Design"
              description="Sleek and responsive design using Tailwind CSS utility classes."
            />
            <FeatureCard
              icon={<Globe size={48} />}
              title="Scalable"
              description="Easily extend and build upon this demo for your next project."
            />
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="bg-gray-800 text-white p-4 text-center">
        <p>&copy; 2024 React TypeScript Demo</p>
      </footer>
    </div>
  );
};

export default App;
