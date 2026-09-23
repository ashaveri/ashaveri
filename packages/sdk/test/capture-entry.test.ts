import { describe, expect, it } from 'vitest';
import { assessCapture, CAPTURE_FORMAT_VERSION, captureRecordKey, parseCaptureRecord } from '../src/index.js';

/**
 * The capture contract is a public statement, so it has to leave the package through its entry point.
 *
 * The reader and the record were first written as a module with tests that reached it by relative path,
 * which is green whether or not anything outside this package can import it. A consumer reading
 * `docs/capture-v1.md` is told to check a record with this code, so the only shape of that promise that
 * can be checked is an import from the entry every other public symbol leaves by.
 */
describe('capture contract reachability from the package entry', () => {
  it('hands a consumer the four things a capture check needs', () => {
    expect(typeof parseCaptureRecord, 'the record is parseable from outside').toBe('function');
    expect(typeof captureRecordKey, 'and identifiable by a key a store can deduplicate on').toBe('function');
    expect(typeof assessCapture, 'and assessable against pinned roots').toBe('function');
    expect(CAPTURE_FORMAT_VERSION, 'with the version the layout names').toBe(1);
  });
});
