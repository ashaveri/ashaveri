import { describe, expect, it } from 'vitest';
import {
  MINIMUM_RETENTION_SECONDS,
  openMemoryReceiptStore,
  RECEIPT_STORE_FILE,
  StoreError,
  type ReceiptStore,
} from '../src/index.js';

/**
 * The evidence-pack generator is a separate program that reads a live store through this package's
 * entry point, so the entry point is a public interface even though nothing imports it from inside
 * this repository. These tests are what make removing one of these exports a decision rather than a
 * tidy-up.
 */
describe('the package entry point', () => {
  it('hands out the same store engine the gateway opens', async () => {
    const store: ReceiptStore = openMemoryReceiptStore();
    await store.put('r1', Uint8Array.from([1, 2, 3]), 1_000);
    await store.put('r2', Uint8Array.from([4, 5, 6]), 2_000);

    expect(await store.window()).toEqual({ from: 1_000, to: 2_000, count: 2 });
    expect(await store.get('r1')).toEqual(Uint8Array.from([1, 2, 3]));

    const head = await store.head();
    const chain = await store.chainState();
    expect(head.length).toBe(32);
    expect(chain.anchor.length).toBe(32);
    expect(chain.retired).toEqual({ byAge: 0, byCount: 0, trims: [] });
  });

  it('names the file an operator backs up and the floor the manifest copies', () => {
    expect(RECEIPT_STORE_FILE).toBe('receipts.log');
    expect(MINIMUM_RETENTION_SECONDS).toBe(184 * 24 * 60 * 60);
  });

  it('carries the one code a store refuses with', () => {
    expect(new StoreError('STORE_CHAIN_BROKEN', 'record 3 does not chain').code).toBe('STORE_CHAIN_BROKEN');
  });
});
