import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  decodeSealedDeploymentManifest,
  generateSigningKey,
  hashRequest,
  signingKeyFromSeed,
  toHex,
  type SigningKey,
} from '@ashaveri/receipt';
import { mockDeployment, type Deployment } from '../src/deployment.js';
import {
  EPOCH_JOURNAL_FILE,
  EpochJournalError,
  openEpochJournal,
  type EpochJournal,
} from '../src/epoch-journal.js';
import type { TimeSource } from '../src/store.js';
import { fixedClock, generated, harness, type Harness } from './helpers.js';

/**
 * The history a journal holds, published as the deployment's own document.
 *
 * Section 4.4 of `docs/receipt-spec.md` states what a `keys[]` entry means when it names an epoch and a start,
 * and the rules a history is read by are `parseManifest`'s. What had no writer until now was the deployment
 * side of that: the served document held the one key the process stood on, so a rotation dropped the
 * predecessor and every receipt issued under it stopped being answerable. These cases take the entries a
 * running process recorded and read them back out of the route a client reads them from, which is the whole of
 * the claim this mechanism makes: what a deployment publishes about its own keys is what it wrote down while
 * serving under them.
 *
 * Two shapes of served document appear below, because a deployment is in one of two states. Without a sealing
 * key the route answers with the plain JSON document, and a client that designated no key reads it as
 * unauthenticated; with one, the same bytes arrive inside a signature. More than one entry is published only
 * in the second state, and the case that shows the refusal shows the reason: a document stating which key was
 * retired and when is a claim about the past, and unsigned it is nobody's claim.
 *
 * The reader's rules are reached from the package that owns them rather than restated here. `parseManifest`
 * and `adjudicateReceiptEpoch` come from the built client package by its own path, the way this suite already
 * reaches the offline verifier: the gateway does not depend on the client package, and a gateway that imported
 * it would ask for a build order the workspace cannot answer. A second copy of those rules in this file would
 * be the defect `gateway/src/index.ts` names, so there is none.
 */

const CREDENTIAL = 'epoch-journal-serving';
const FIRST_INSTANT = 1_772_000_000;
const SECOND_INSTANT = 1_772_003_600;
const THIRD_INSTANT = SECOND_INSTANT + 600;

const SEAL_KEY = signingKeyFromSeed(hashRequest(new TextEncoder().encode('ashaveri-epoch-journal-seal-key')));

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** A served row, in the two shapes it takes: the current key alone, or that key beside its history. */
interface ServedRow {
  kid: string;
  alg: string;
  publicKey: string;
  epk?: number;
  validFrom?: number;
}

/** The client package's reader, reached from its build rather than copied into this package. */
interface ClientManifestReader {
  parseManifest(value: unknown): ParsedManifest;
  adjudicateReceiptEpoch(
    manifest: ParsedManifest,
    claim: { kid: string; epoch: number; issuedAt: number },
  ): {
    ok: boolean;
    basis?: string;
    validFrom?: number | null;
    validTo?: number | null;
    superseded?: boolean;
    code?: string;
    detail?: string;
  };
}

interface ParsedManifest {
  epk: number;
  keys: readonly ServedRow[];
  epochs:
    | readonly { epoch: number; validFrom: number; validTo: number | null; kids: readonly string[] }[]
    | null;
}

const client = (await import(
  new URL('../../packages/sdk/dist/index.js', import.meta.url).href
)) as ClientManifestReader;

const gateways: Harness[] = [];
const volumes: string[] = [];

afterEach(async () => {
  for (const app of gateways.splice(0)) await app.app.close();
  for (const dir of volumes.splice(0)) await rm(dir, { recursive: true, force: true });
});

async function volume(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-epoch-journal-serving-'));
  volumes.push(dir);
  return dir;
}

/**
 * One boot of a deployment over one volume: the journal is opened from the key and the epoch this process holds
 * and the source it stamps by, and then handed to the gateway that publishes it. `withSeal` is the operator's
 * `--manifest-key-path`, and the journal is told the same answer because it refuses to record what the run
 * would refuse to serve.
 */
async function boot(dir: string, key: SigningKey, epoch: number, at: number, withSeal: boolean): Promise<Booted> {
  const time: TimeSource = fixedClock(() => at, 3);
  const journal = await openEpochJournal({ dir, key, epk: epoch, sealed: withSeal, time });
  const deployment: Deployment = mockDeployment({
    key,
    epk: epoch,
    time,
    ...(withSeal ? { manifestKey: SEAL_KEY } : {}),
  });
  const app = await harness({
    credentials: [generated(CREDENTIAL, ['read', 'complete'])],
    gateway: { deployment, epochJournal: journal, time },
  });
  gateways.push(app);
  return {
    journal,
    deployment,
    async served(): Promise<Uint8Array> {
      const response = await app.app.inject({
        method: 'GET',
        url: '/v1/deployment-manifest',
        headers: app.signFor(CREDENTIAL, 'GET', '/v1/deployment-manifest', null),
      });
      expect(response.statusCode).toBe(200);
      return new Uint8Array(response.rawPayload);
    },
  };
}

interface Booted {
  readonly journal: EpochJournal;
  readonly deployment: Deployment;
  served(): Promise<Uint8Array>;
}

/** The document behind a sealed response, read as a client reads it: the signed payload bytes, decoded. */
function sealedDocument(bytes: Uint8Array): unknown {
  return JSON.parse(new TextDecoder().decode(decodeSealedDeploymentManifest(bytes).payloadBytes));
}

function servedDocument(bytes: Uint8Array): unknown {
  const text = new TextDecoder().decode(bytes);
  return text.startsWith('{') ? JSON.parse(text) : sealedDocument(bytes);
}

function servedKeys(bytes: Uint8Array): ServedRow[] {
  return (servedDocument(bytes) as { keys: ServedRow[] }).keys;
}

describe('a served manifest that publishes the journal beside it', () => {
  it('states the window of the one epoch it holds as plain JSON, which claims no history', async () => {
    const dir = await volume();
    const key = signingKeyFromSeed(utf8('ashaveri-epoch-journal-serving-l'));
    const booted = await boot(dir, key, 1, FIRST_INSTANT, false);
    const served = await booted.served();
    expect(servedKeys(served)).toEqual([
      {
        kid: toHex(key.kid),
        alg: 'Ed25519',
        publicKey: Buffer.from(key.publicKey).toString('base64url'),
        epk: 1,
        validFrom: FIRST_INSTANT,
      },
    ]);
    // Read by the rules the client reads by: one declared window, and no end published for the highest epoch.
    expect(client.parseManifest(servedDocument(served)).epochs).toEqual([
      { epoch: 1, validFrom: FIRST_INSTANT, validTo: null, kids: [toHex(key.kid)] },
    ]);
  });

  it('publishes both entries after a second epoch, each with the instant its own window opened at', async () => {
    const dir = await volume();
    const first = signingKeyFromSeed(utf8('ashaveri-epoch-journal-serving-a'));
    const second = signingKeyFromSeed(utf8('ashaveri-epoch-journal-serving-b'));
    await boot(dir, first, 1, FIRST_INSTANT, true);
    const rotated = await boot(dir, second, 2, SECOND_INSTANT, true);
    expect(rotated.journal.entries).toHaveLength(2);
    expect(servedKeys(await rotated.served())).toEqual([
      {
        kid: toHex(first.kid),
        alg: 'Ed25519',
        publicKey: Buffer.from(first.publicKey).toString('base64url'),
        epk: 1,
        validFrom: FIRST_INSTANT,
      },
      {
        kid: toHex(second.kid),
        alg: 'Ed25519',
        publicKey: Buffer.from(second.publicKey).toString('base64url'),
        epk: 2,
        validFrom: SECOND_INSTANT,
      },
    ]);
    // The published window closes where the successor opens, and the successor has no end published: the upper
    // bound is a fact of the entry beside it, and no deployment writes a second number that has to agree.
    const parsed = client.parseManifest(servedDocument(await rotated.served()));
    expect(parsed).toMatchObject({ epk: 2 });
    expect(parsed.epochs).toEqual([
      { epoch: 1, validFrom: FIRST_INSTANT, validTo: SECOND_INSTANT, kids: [toHex(first.kid)] },
      { epoch: 2, validFrom: SECOND_INSTANT, validTo: null, kids: [toHex(second.kid)] },
    ]);
  });

  it('admits a receipt of the superseded epoch through its window and answers one outside it', async () => {
    const dir = await volume();
    const first = signingKeyFromSeed(utf8('ashaveri-epoch-journal-serving-c'));
    const second = signingKeyFromSeed(utf8('ashaveri-epoch-journal-serving-d'));
    await boot(dir, first, 1, FIRST_INSTANT, true);
    const rotated = await boot(dir, second, 2, SECOND_INSTANT, true);
    const manifest = client.parseManifest(servedDocument(await rotated.served()));
    const retired = toHex(first.kid);
    // Inside the window this deployment recorded for its own earlier key: admitted on the stronger basis, and
    // named as superseded, because a current epoch has since opened. The weaker reading, which a document
    // without windows falls to, states no bound at all.
    expect(
      client.adjudicateReceiptEpoch(manifest, { kid: retired, epoch: 1, issuedAt: SECOND_INSTANT - 1 }),
    ).toMatchObject({
      ok: true,
      basis: 'windows',
      validFrom: FIRST_INSTANT,
      validTo: SECOND_INSTANT,
      superseded: true,
    });
    // The instant a successor opens belongs to the successor, so a stamp there is outside the retired key's
    // window, and the refusal names both bounds it was weighed against.
    const late = client.adjudicateReceiptEpoch(manifest, { kid: retired, epoch: 1, issuedAt: SECOND_INSTANT });
    expect(late).toMatchObject({ ok: false, code: 'MANIFEST_EPOCH_DISAGREES' });
    expect(late.detail).toContain(`outside the epoch 1 window of ${FIRST_INSTANT} to ${SECOND_INSTANT}`);
    // And an epoch this journal never named is not answered by this document at all, which is the sentence a
    // deployment that back-fills nothing has to be able to say.
    const straying = client.adjudicateReceiptEpoch(manifest, { kid: retired, epoch: 7, issuedAt: FIRST_INSTANT });
    expect(straying).toMatchObject({ ok: false, code: 'MANIFEST_EPOCH_UNDECLARED' });
    expect(straying.detail).toContain('which publishes 1, 2');
  });

  it('refuses to serve a history it cannot sign, and still serves the single epoch it holds', async () => {
    const dir = await volume();
    const first = signingKeyFromSeed(utf8('ashaveri-epoch-journal-serving-e'));
    const second = signingKeyFromSeed(utf8('ashaveri-epoch-journal-serving-f'));
    // A journal of two epochs, recorded under a sealing key this later run does not hold: what the served
    // document would say about the retired key is a claim no signature stands behind.
    await boot(dir, first, 1, FIRST_INSTANT, true);
    const rotated = await boot(dir, second, 2, SECOND_INSTANT, true);
    expect(rotated.journal.entries).toHaveLength(2);
    const unsealedTime: TimeSource = fixedClock(() => THIRD_INSTANT);
    const unsealed = mockDeployment({ key: second, epk: 2, time: unsealedTime });
    await expect(
      harness({
        credentials: [generated(CREDENTIAL, ['read', 'complete'])],
        gateway: { deployment: unsealed, epochJournal: rotated.journal, time: unsealedTime },
      }),
    ).rejects.toThrowError(EpochJournalError);
    await expect(
      harness({
        credentials: [generated(CREDENTIAL, ['read', 'complete'])],
        gateway: { deployment: unsealed, epochJournal: rotated.journal, time: unsealedTime },
      }),
    ).rejects.toThrowError(/history that signs nothing/u);
    // One entry, no sealing key: today's document, and the run serves.
    const plainDir = await volume();
    const only = await boot(plainDir, first, 1, FIRST_INSTANT, false);
    expect(only.journal.entries).toHaveLength(1);
    expect((await only.served()).length).toBeGreaterThan(0);
  });

  it('refuses to record a second epoch it could not publish, and leaves the journal one entry deep', async () => {
    const dir = await volume();
    const first = signingKeyFromSeed(utf8('ashaveri-epoch-journal-serving-g'));
    const second = signingKeyFromSeed(utf8('ashaveri-epoch-journal-serving-h'));
    await boot(dir, first, 1, FIRST_INSTANT, false);
    const path = join(dir, EPOCH_JOURNAL_FILE);
    const before = await readFile(path);
    await expect(
      openEpochJournal({
        dir,
        key: second,
        epk: 2,
        sealed: false,
        time: fixedClock(() => SECOND_INSTANT, 3),
      }),
    ).rejects.toThrowError(/history that signs nothing/u);
    expect((await readFile(path)).equals(before)).toBe(true);
  });

  it('leaves a deployment that keeps no journal publishing the one key it stands on', async () => {
    const key = generateSigningKey();
    const app = await harness({
      credentials: [generated(CREDENTIAL, ['read', 'complete'])],
      gateway: { deployment: mockDeployment({ key }) },
    });
    gateways.push(app);
    const response = await app.app.inject({
      method: 'GET',
      url: '/v1/deployment-manifest',
      headers: app.signFor(CREDENTIAL, 'GET', '/v1/deployment-manifest', null),
    });
    const document = response.json() as { keys: ServedRow[] };
    expect(document.keys).toHaveLength(1);
    expect(Object.keys(document.keys[0]!).sort()).toEqual(['alg', 'kid', 'publicKey']);
    // No window is stated, so a reader falls to the weaker rule and says which one it used. This is the
    // document a deployment serves when it keeps no volume, and the state the journal replaces.
    const parsed = client.parseManifest(document);
    expect(parsed.epochs).toBeNull();
    expect(
      client.adjudicateReceiptEpoch(parsed, { kid: toHex(key.kid), epoch: 0, issuedAt: FIRST_INSTANT }),
    ).toMatchObject({ ok: true, basis: 'current-epoch', validFrom: null, validTo: null });
  });
});

describe('a published history that a rewritten journal would have invented', () => {
  it('refuses a gateway whose journal was edited after it was written, and names the file', async () => {
    const dir = await volume();
    const first = signingKeyFromSeed(utf8('ashaveri-epoch-journal-serving-i'));
    const second = signingKeyFromSeed(utf8('ashaveri-epoch-journal-serving-j'));
    const third = signingKeyFromSeed(utf8('ashaveri-epoch-journal-serving-k'));
    await boot(dir, first, 1, FIRST_INSTANT, true);
    await boot(dir, second, 2, SECOND_INSTANT, true);
    const path = join(dir, EPOCH_JOURNAL_FILE);
    const filed = JSON.parse((await readFile(path)).toString('utf8')) as {
      entries: { validFrom: number }[];
    };
    // Moving the first window to the second one's instant is the edit a silent rewrite looks like: the
    // document is still parseable JSON, its own entries no longer digest to what its successors state.
    filed.entries[0]!.validFrom = SECOND_INSTANT;
    await writeFile(path, JSON.stringify(filed));
    await expect(
      openEpochJournal({ dir, key: third, epk: 3, sealed: true, time: fixedClock(() => THIRD_INSTANT, 3) }),
    ).rejects.toThrowError(path);
  });
});
