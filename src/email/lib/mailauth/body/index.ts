import { SimpleHash } from './simple.ts';
import { RelaxedHash } from './relaxed.ts';

export const dkimBody = (
  canonicalization: any,
  ...options: [string, number]
) => {
  canonicalization = (canonicalization ?? 'simple/simple')
    .toString()
    .split('/')
    .pop()
    ?.toLowerCase()
    .trim();
  switch (canonicalization) {
    case 'simple':
      return new SimpleHash(...options);
    case 'relaxed':
      return new RelaxedHash(...options);
    default:
      throw new Error('Unknown body canonicalization');
  }
};
