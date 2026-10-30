import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { hashRequest, signingKeyFromSeed } from '@ashaveri/receipt';
import { mockDeployment } from '../src/deployment.js';
import {
  EPOCH_JOURNAL_FILE,
  EPOCH_JOURNAL_VERSION,
  EpochJournalError,
  openEpochJournal,
  recordEpochForRun,
} from '../src/epoch-journal.js';
import { openFileReceiptStore, type TimeSource } from '../src/store.js';
import { fixedClock } from './helpers.js';

/**
 * What the journal beside a receipt volume records, and what it refuses to.
 *
 * A deployment's rotation history is two optional members of a manifest's `keys[]` entry, and the format has
 * carried them since section 4.4 of `docs/receipt-spec.md` described them while nothing in the estate wrote
 * them: the served document held the one key the process stood on, so a rotation published by the shipped
 * binary dropped the predecessor's key and its window, and a receipt from before the rotation stopped
 * verifying. This file is about the writer. The rules it holds are the ones a writer owes its own readers: an
 * entry comes from the epoch it describes, an entry already written is never rewritten, a restart records
 * nothing, the instant an entry names is whole seconds and never behind an instant already published, and the
 * clock that read it is named beside it.
 *
 * The rules about the *shape of a history*, one epoch declared with two starts and starts that do not ascend,
 * are deliberately absent here. Those live in `parseManifest` and are read by every client that reaches a
 * deployment through its document; `test/epoch-journal-serving.test.ts` holds the served document against
 * that one copy rather than restating it a second time.
 */

const FIRST_INSTANT = 1_772_000_000;
const SECOND_INSTANT = 1_772_003_600;

const FIRST_KEY = signingKeyFromSeed(hashRequest(new TextEncoder().encode('ashaveri-epoch-journal-first-key')));
const SECOND_KEY = signingKeyFromSeed(hashRequest(new TextEncoder().encode('ashaveri-epoch-journal-second-key')));
const SEAL_KEY = signingKeyFromSeed(hashRequest(new TextEncoder().encode('ashaveri-epoch-journal-seal-key')));

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** A clock pinned to an instant a case moves, which is the only way a window opening is knowable in a test. */
function clockAt(start: number): { time: TimeSource; move(to: number): void } {
  const state = { at: start };
  return {
    time: fixedClock(() => state.at, 3),
    move(to: number): void {
      state.at = to;
    },
  };
}

const swept: string[] = [];

afterEach(async () => {
  for (const dir of swept.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

/** One volume per case: the journal and the receipt store share it, exactly as a deployment's files do. */
async function volume(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-epoch-journal-'));
  swept.push(dir);
  return dir;
}

async function journalBytes(dir: string, name = EPOCH_JOURNAL_FILE): Promise<Buffer> {
  return readFile(join(dir, name));
}

/** One entry as it is filed, spelled out so a case can move a member of it and prove the refusal. */
interface FiledEntry {
  epk: number;
  kid: string;
  publicKey: string;
  validFrom: number;
  stamped: { name: string; uncertaintySeconds: number | null };
  prev: string;
}

function document(bytes: Buffer): { v: number; entries: FiledEntry[] } {
  return JSON.parse(bytes.toString('utf8')) as { v: number; entries: FiledEntry[] };
}

describe('a journal recording the epoch it is standing in', () => {
  it('writes exactly one entry on the first boot under a fresh epoch', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    const journal = await openEpochJournal({
      dir,
      key: FIRST_KEY,
      epk: 1,
      sealed: true, time: clock.time,
    });
    expect(journal.path).toBe(join(dir, EPOCH_JOURNAL_FILE));
    expect(journal.entries).toHaveLength(1);
    expect(journal.entries[0]).toEqual({
      epk: 1,
      kid: Buffer.from(FIRST_KEY.kid).toString('hex'),
      publicKey: Buffer.from(FIRST_KEY.publicKey).toString('base64url'),
      validFrom: FIRST_INSTANT,
      stamped: { name: 'fixture clock', uncertaintySeconds: 3 },
      prev: expect.stringMatching(/^[0-9a-f]{64}$/u),
    });
    expect(journal.appended).toEqual(journal.entries[0]);
    const filed = document(await journalBytes(dir));
    expect(filed.v).toBe(EPOCH_JOURNAL_VERSION);
    expect(filed.entries).toEqual(journal.entries);
  });

  it('leaves the file byte-identical when the same epoch restarts under the same key', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    const first = await openEpochJournal({ dir, key: FIRST_KEY, epk: 1, sealed: true, time: clock.time });
    const before = await journalBytes(dir);
    clock.move(FIRST_INSTANT + 600);
    const again = await openEpochJournal({ dir, key: FIRST_KEY, epk: 1, sealed: true, time: clock.time });
    expect(again.entries).toHaveLength(1);
    // Nothing is rewritten, not merely rewritten to the same value: an entry the same process wrote a
    // moment ago and a rewrite of it are the same bytes, so the claim has to be about the file.
    expect(again.appended).toBeNull();
    expect((await journalBytes(dir)).equals(before)).toBe(true);
    expect(again.entries[0]).toEqual(first.entries[0]);
  });

  it('appends a second epoch beside the first, each entry naming the instant it opened at', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    await openEpochJournal({ dir, key: FIRST_KEY, epk: 1, sealed: true, time: clock.time });
    clock.move(SECOND_INSTANT);
    const second = await openEpochJournal({ dir, key: SECOND_KEY, epk: 2, sealed: true, time: clock.time });
    expect(second.entries.map((entry) => [entry.epk, entry.validFrom])).toEqual([
      [1, FIRST_INSTANT],
      [2, SECOND_INSTANT],
    ]);
    expect(second.entries[1]!.kid).toBe(Buffer.from(SECOND_KEY.kid).toString('hex'));
    expect(second.entries[0]!.kid).toBe(Buffer.from(FIRST_KEY.kid).toString('hex'));
    expect(second.appended).toEqual(second.entries[1]);
  });

  it('records a new key under an epoch it already names, because the pair is what is idempotent', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    await openEpochJournal({ dir, key: FIRST_KEY, epk: 1, sealed: true, time: clock.time });
    clock.move(SECOND_INSTANT);
    const moved = await openEpochJournal({ dir, key: SECOND_KEY, epk: 1, sealed: true, time: clock.time });
    expect(moved.entries.map((entry) => [entry.epk, entry.kid.slice(0, 8)])).toEqual([
      [1, Buffer.from(FIRST_KEY.kid).toString('hex').slice(0, 8)],
      [1, Buffer.from(SECOND_KEY.kid).toString('hex').slice(0, 8)],
    ]);
    expect(moved.appended).not.toBeNull();
  });

  it('starts a fresh journal on a volume that holds none, and adds nothing when the epoch is the one it holds', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    const only = await openEpochJournal({ dir, key: FIRST_KEY, epk: 0, sealed: true, time: clock.time });
    expect(only.entries).toHaveLength(1);
    expect(only.entries[0]).toMatchObject({ epk: 0, validFrom: FIRST_INSTANT });
  });

  it('names the source that read the instant, which is the difference between a bound and a silence', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    const journal = await openEpochJournal({ dir, key: FIRST_KEY, epk: 1, sealed: true, time: clock.time });
    expect(journal.entries[0]!.stamped).toEqual({ name: 'fixture clock', uncertaintySeconds: 3 });
    const unwired = await openEpochJournal({
      dir,
      file: 'host-clock.json',
      key: SECOND_KEY,
      epk: 1,
      sealed: true,
    });
    // Absent is the shipped state, and it has its own sentence: this host's own claim at a bound nobody
    // measured, which a reader weighs differently from a source somebody bounded.
    expect(unwired.entries[0]!.stamped).toEqual({ name: 'host clock', uncertaintySeconds: null });
  });

  it('floors a second-granular stamp at whole seconds rather than publishing a fraction', async () => {
    const dir = await volume();
    const journal = await openEpochJournal({
      dir,
      key: FIRST_KEY,
      epk: 1,
      sealed: true, time: { name: 'fractional clock', uncertaintySeconds: null, nowSeconds: () => FIRST_INSTANT + 0.75 },
    });
    expect(journal.entries[0]!.validFrom).toBe(FIRST_INSTANT);
    expect(Number.isSafeInteger(journal.entries[0]!.validFrom)).toBe(true);
  });
});

describe('a journal that refuses rather than publishes', () => {
  it('refuses a document whose existing entries were rewritten, and names the file it read', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    await openEpochJournal({ dir, key: FIRST_KEY, epk: 1, sealed: true, time: clock.time });
    clock.move(SECOND_INSTANT);
    await openEpochJournal({ dir, key: SECOND_KEY, epk: 2, sealed: true, time: clock.time });
    const path = join(dir, EPOCH_JOURNAL_FILE);
    const edited = document(await readFile(path));
    // The predecessor's key is the entry a reader of a superseded receipt depends on. Moving one byte of
    // it, in place, with the file otherwise well formed, is the edit this check exists to meet.
    edited.entries[0]!.publicKey = edited.entries[1]!.publicKey;
    await writeFile(path, JSON.stringify(edited));
    const third = signingKeyFromSeed(hashRequest(utf8('ashaveri-epoch-journal-third-key')));
    clock.move(SECOND_INSTANT + 600);
    await expect(openEpochJournal({ dir, key: third, epk: 3, sealed: true, time: clock.time })).rejects.toThrowError(
      /rewritten or removed/u,
    );
    await expect(openEpochJournal({ dir, key: third, epk: 3, sealed: true, time: clock.time })).rejects.toThrowError(path);
    // Refused before anything was written: the volume holds the edited document the case made, not a
    // third entry resting on it.
    expect(document(await readFile(path)).entries).toHaveLength(2);
  });

  it('refuses an instant that does not follow the one already recorded, and leaves the file as it was', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    await openEpochJournal({ dir, key: FIRST_KEY, epk: 1, sealed: true, time: clock.time });
    const before = await journalBytes(dir);
    const stepped = signingKeyFromSeed(hashRequest(utf8('ashaveri-epoch-journal-stepped-key')));
    // The same instant the first epoch opened at: an entry there would state two windows opening together,
    // which is a history no reader can walk, so the run stops instead of publishing it.
    await expect(openEpochJournal({ dir, key: stepped, epk: 2, sealed: true, time: clock.time })).rejects.toThrowError(
      /does not follow it/u,
    );
    clock.move(FIRST_INSTANT - 500);
    await expect(openEpochJournal({ dir, key: stepped, epk: 2, sealed: true, time: clock.time })).rejects.toThrowError(
      EpochJournalError,
    );
    expect((await journalBytes(dir)).equals(before)).toBe(true);
  });

  it('refuses a document that is not a journal, and an epoch that is not a whole number', async () => {
    const dir = await volume();
    await writeFile(join(dir, 'not-a-journal.json'), '{ this is not JSON');
    await expect(
      openEpochJournal({ dir, file: 'not-a-journal.json', key: FIRST_KEY, epk: 1, sealed: true, time: fixedClock(() => FIRST_INSTANT) }),
    ).rejects.toThrowError(/not readable as JSON/u);

    await writeFile(join(dir, 'other-version.json'), JSON.stringify({ v: 7, entries: [] }));
    await expect(
      openEpochJournal({ dir, file: 'other-version.json', key: FIRST_KEY, epk: 1, sealed: true, time: fixedClock(() => FIRST_INSTANT) }),
    ).rejects.toThrowError(/states version 7/u);

    await expect(
      openEpochJournal({ dir, key: FIRST_KEY, epk: 1.5, sealed: true, time: fixedClock(() => FIRST_INSTANT) }),
    ).rejects.toThrowError(/epoch 1\.5, which is not a whole number/u);
  });

  it('writes through a temporary file and leaves nothing of the move behind', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    await openEpochJournal({ dir, key: FIRST_KEY, epk: 1, sealed: true, time: clock.time });
    clock.move(SECOND_INSTANT);
    await openEpochJournal({ dir, key: SECOND_KEY, epk: 2, sealed: true, time: clock.time });
    const held = await readFile(join(dir, EPOCH_JOURNAL_FILE), 'utf8');
    expect(held).toContain('"epk":2');
    await expect(journalBytes(dir, `${EPOCH_JOURNAL_FILE}.appending`)).rejects.toThrowError(/ENOENT/u);
  });
});

describe('a journal that is not receipts', () => {
  it('outlives the retirement of every receipt whose epoch it explains', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    const journal = await openEpochJournal({ dir, key: FIRST_KEY, epk: 1, sealed: true, time: clock.time });
    const before = await journalBytes(dir);
    // The same volume, the same source, and a period short enough that the store retires what it is given.
    // The journal is operational state about keys, not personal data, so no window on receipts reaches it.
    const store = await openFileReceiptStore({
      dir,
      retention: { maxAgeSeconds: 60, time: clock.time },
    });
    await store.put('receipt-before-window', utf8('a signed receipt'), FIRST_INSTANT);
    clock.move(FIRST_INSTANT + 120);
    await store.put('receipt-after-window', utf8('a second signed receipt'), FIRST_INSTANT + 120);
    expect(await store.get('receipt-before-window')).toBeNull();
    const window = await store.window();
    expect(window.count).toBe(1);
    expect((await journalBytes(dir)).equals(before)).toBe(true);
    expect(journal.entries[0]).toMatchObject({ epk: 1, validFrom: FIRST_INSTANT });
    // And a second boot over that volume reads the journal the retirement left alone, and appends to it.
    clock.move(SECOND_INSTANT);
    const second = await openEpochJournal({ dir, key: SECOND_KEY, epk: 2, sealed: true, time: clock.time });
    expect(second.entries.map((entry) => entry.epk)).toEqual([1, 2]);
  });
});

describe('the run a binary hands the journal', () => {
  it('records nothing where the run keeps no receipts, and files no journal behind it', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    const journal = await recordEpochForRun({
      receiptsDir: undefined,
      mock: false,
      deployment: mockDeployment({ key: FIRST_KEY, manifestKey: SEAL_KEY, epk: 1, time: clock.time }),
      time: clock.time,
    });
    expect(journal).toBeUndefined();
    // A volume that was never pointed at is not written to, so the answer is not a journal of no entries.
    await expect(journalBytes(dir)).rejects.toThrowError(/ENOENT/u);
  });

  it('records nothing for a mock run, because its key is generated with the process and dropped by it', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    const journal = await recordEpochForRun({
      receiptsDir: dir,
      mock: true,
      deployment: mockDeployment({ key: FIRST_KEY, manifestKey: SEAL_KEY, epk: 1, time: clock.time }),
      time: clock.time,
    });
    expect(journal).toBeUndefined();
    await expect(journalBytes(dir)).rejects.toThrowError(/ENOENT/u);
  });

  it('records the second epoch for a run holding a sealing key, which is the rotation a deployment performs', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    const first = await recordEpochForRun({
      receiptsDir: dir,
      mock: false,
      deployment: mockDeployment({ key: FIRST_KEY, manifestKey: SEAL_KEY, epk: 1, time: clock.time }),
      time: clock.time,
    });
    expect(first?.entries).toHaveLength(1);
    clock.move(SECOND_INSTANT);
    const rotated = await recordEpochForRun({
      receiptsDir: dir,
      mock: false,
      deployment: mockDeployment({ key: SECOND_KEY, manifestKey: SEAL_KEY, epk: 2, time: clock.time }),
      time: clock.time,
    });
    expect(rotated?.entries.map((entry) => entry.epk)).toEqual([1, 2]);
    expect(rotated?.appended).toMatchObject({ epk: 2, validFrom: SECOND_INSTANT });
  });

  it('refuses the same rotation for a run holding no sealing key, and files nothing it could not publish', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    await recordEpochForRun({
      receiptsDir: dir,
      mock: false,
      deployment: mockDeployment({ key: FIRST_KEY, epk: 1, time: clock.time }),
      time: clock.time,
    });
    clock.move(SECOND_INSTANT);
    await expect(
      recordEpochForRun({
        receiptsDir: dir,
        mock: false,
        deployment: mockDeployment({ key: SECOND_KEY, epk: 2, time: clock.time }),
        time: clock.time,
      }),
    ).rejects.toThrowError(EpochJournalError);
    // The seal answer is read out of the deployment rather than stated beside it, so a run that was handed no
    // manifest key is the only one that meets this refusal, and the file still holds the one entry recorded.
    expect(document(await journalBytes(dir)).entries.map((entry) => entry.epk)).toEqual([1]);
  });

  it('records the epoch and key of the deployment it is handed, which is the one fact it may not be told', async () => {
    const dir = await volume();
    const clock = clockAt(FIRST_INSTANT);
    const journal = await recordEpochForRun({
      receiptsDir: dir,
      mock: false,
      deployment: mockDeployment({ key: SECOND_KEY, manifestKey: SEAL_KEY, epk: 7, time: clock.time }),
      time: clock.time,
    });
    const entry = journal?.entries[0];
    expect(entry).toMatchObject({
      epk: 7,
      kid: Buffer.from(SECOND_KEY.kid).toString('hex'),
      publicKey: Buffer.from(SECOND_KEY.publicKey).toString('base64url'),
    });
  });
});
