import { defineConfig } from 'vite';
import { resolve } from 'path';

const root = resolve(__dirname, 'src');

export default defineConfig({
  root,
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: resolve(root, 'popup', 'popup.html'),
        background: resolve(root, 'background.js'),
        proof: resolve(root, 'proof', 'proof.html'),
      },
      output: {
        entryFileNames: '[name].js',
      },
    },
  },
  publicDir: resolve(__dirname, 'public'),
  resolve: {
    alias: {
      o1js: resolve(__dirname, '../node_modules/o1js'),
    },
  },
});
