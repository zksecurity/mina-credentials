import React, { createContext, useContext, useCallback, useState } from 'react';

type Toast = {
  id: number;
  title: string;
  description?: string;
  className?: string;
};

type ToastContextType = {
  toast: (props: Omit<Toast, 'id'>) => void;
};

const ToastContext = createContext<ToastContextType | null>(null);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((props: Omit<Toast, 'id'>) => {
    const id = Date.now();
    setToasts((current) => [...current, { ...props, id }]);
    setTimeout(() => {
      setToasts((current) => current.filter((t) => t.id !== id));
    }, 3000);
  }, []);

  return (
    <ToastContext.Provider value={{ toast: addToast }}>
      {children}
      <div className="fixed bottom-0 right-0 p-4 space-y-2 z-50">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`p-4 rounded-lg shadow-lg max-w-sm ${toast.className}`}
          >
            {toast.title && <div className="font-semibold">{toast.title}</div>}
            {toast.description && (
              <div className="text-sm">{toast.description}</div>
            )}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => {
  const context = useContext(ToastContext);
  if (!context) throw new Error('useToast must be used within ToastProvider');
  return context;
};
