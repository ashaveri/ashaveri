import { describe, expect, it } from 'vitest';
import {
  MINIMUM_RETENTION_SECONDS,
  openMemoryReceiptStore,
  receiptsNeededForWindow,
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

  it('carries the three codes a store refuses with', () => {
    // Three, because there are three things a store can object to: the file it was handed, the value a
    // caller is asking it to write now, and the pairing a configuration asked it to open with. A
    // refusal that reached a caller under the first name when the second or third was meant would send
    // an operator to the volume with nothing wrong on it.
    expect(new StoreError('STORE_CHAIN_BROKEN', 'record 3 does not chain').code).toBe('STORE_CHAIN_BROKEN');
    expect(new StoreError('RECORD_STAMP_OUT_OF_RANGE', 'a stamp of 1.5 is not a whole second').code).toBe(
      'RECORD_STAMP_OUT_OF_RANGE',
    );
    expect(
      new StoreError('RETENTION_WINDOW_UNHOLDABLE', 'this store is at its bound of 50 receipts').code,
    ).toBe('RETENTION_WINDOW_UNHOLDABLE');
  });

  it('hands out the arithmetic a refusing store refuses by', async () => {
    // The count bound is configuration and the refusal is derived from it, so the arithmetic behind the
    // message has to be readable by whoever sets the number. A second copy of it where the number is
    // written would drift from the one here, and the message an operator acts on would stop naming the
    // count the store actually needed.
    //
    // The retained set is one receipt a second across ten seconds, so the traffic the store reports is
    // one receipt a second and a ten second window takes the eleventh that lands past its older edge.
    // The clock is injected because these are instants in 1970, and an age bound read against the
    // platform clock would retire every one of them before the window was asked for.
    const store: ReceiptStore = openMemoryReceiptStore({
      retention: { maxAgeSeconds: 10, maxCount: 11, now: () => 1_009 },
    });
    for (let i = 0; i < 10; i++) {
      await store.put(`r${String(i)}`, Uint8Array.from([i]), 1_000 + i);
    }
    expect(receiptsNeededForWindow(10, await store.window())).toBe(11);
  });
});
