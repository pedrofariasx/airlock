// @airlock/airlock — umbrella package re-exporting the core engine and the
// universal fetch wrapper. This entry point re-exports the fetch wrapper, which
// is the primary product. Use the subpath imports for direct access:
//   import { ... } from '@airlock/airlock/fetch'  // fetch wrapper
//   import { ... } from '@airlock/airlock/core'   // pure engine

export * from '@airlock/fetch';

export const VERSION = '0.1.0';
