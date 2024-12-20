import * as fs from 'fs';
import * as path from 'path';
import { DATA_PATH } from './config.ts';

export { createJsonStore };

function createJsonStore<T>(fileName: string, defaultValue: T) {
  const filePath = path.join(DATA_PATH, fileName);

  function load(): T {
    if (!fs.existsSync(filePath)) return defaultValue;

    let data = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(data) as T;
  }

  function save(t: T) {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(filePath, JSON.stringify(t), 'utf-8');
    inMemory = t;
  }

  let inMemory = load();

  return {
    get() {
      return inMemory;
    },
    set(t: T) {
      save(t);
    },
    update(fn: (t: T) => T | void): T {
      let newValue = fn(inMemory);
      if (newValue !== undefined) save(newValue);
      else save(inMemory); // value was mutated in place
      return inMemory;
    },
  };
}
