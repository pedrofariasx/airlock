// @veil/core — pure reversible redaction engine. Zero deps, isomorphic.

export { Redactor, Restorer } from './engine.js';
export type { RedactorOptions } from './engine.js';

export {
  DEFAULT_CATEGORIES,
  OPT_IN_CATEGORIES,
  ALL_CATEGORIES,
  SCANNERS,
  scannersFor,
} from './categories.js';
export type { RedactCategory, Match, Scanner } from './categories.js';

export {
  cpfValid,
  cnpjValid,
  pisValid,
  ssnValid,
  cepValid,
  ipv4Valid,
  luhnValid,
  awsSecretValid,
  jwtValid,
} from './validators.js';

export const VERSION = '0.1.0';
