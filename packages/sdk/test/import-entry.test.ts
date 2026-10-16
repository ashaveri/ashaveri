import { describe, expect, it } from 'vitest';
import {
  importEnvelopeKey,
  IMPORT_FORMAT_VERSION,
  normalizeProviderExport,
  parseImportEnvelope,
  readImportEnvelope,
} from '../src/index.js';

/**
 * The import contract is a public statement, so it has to leave the package through its entry point.
 *
 * A test reaching the reader by relative path is green whether or not anything outside this package can
 * import it. A consumer reading `docs/import-v1.md` is told to check an envelope with this code and to key
 * a store on its identity, so the only shape of that promise that can be checked is an import from the
 * entry every other public symbol leaves by.
 */
describe('import contract reachability from the package entry', () => {
  it('hands a consumer the four things an import needs', () => {
    expect(typeof parseImportEnvelope, 'the envelope is parseable from outside').toBe('function');
    expect(typeof readImportEnvelope, 'and readable with the shipped rules').toBe('function');
    expect(typeof importEnvelopeKey, 'and identifiable by a key a store can deduplicate on').toBe('function');
    expect(typeof normalizeProviderExport, 'and derived by the shipped normalization').toBe('function');
    expect(IMPORT_FORMAT_VERSION, 'with the version the layout names').toBe(1);
  });
});
