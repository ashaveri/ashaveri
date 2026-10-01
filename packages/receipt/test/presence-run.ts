import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  ReceiptError,
  encodeEpochInventoryManifest,
  encodeEpochInventoryProtectedHeader,
  epochInventorySigStructure,
  retentionDocumentBytes,
  sealEpochInventory,
  signEpochInventory,
  signingKeyFromSeed,
  toHex,
  type EpochInventoryManifest,
  type EpochInventoryPack,
  type EpochInventoryVerifyOptions,
  type RetentionFamily,
  type SigningKey,
} from '../src/index.js';

/**
 * The bytes the presence fold is asked about, built by this package's own writers.
 *
 * Two suites of this container ask the fold: `presence-fold.test.ts`, which is the fold's own reading, and the
 * reach case in `epoch-inventory.test.ts`, which holds every code the container declares to a case that answers
 * with it. This file is why they do not state the same run twice. A retention manifest is evidence only once an
 * entry of the run seals its digest, so a fixture typed by hand would have to be hashed by hand as well, and the
 * whole point of these artifacts is that the writer wrote them and the entry seals what came out.
 */

export const FOLD_KEY: SigningKey = signingKeyFromSeed(new Uint8Array(32).fill(61));
export const FOLD_RUN_START = 1_700_000_000;
export const FOLD_WINDOW = 1_000;
const DAY = 86_400;

export function foldDigest(label: string): string {
  return toHex(sha256(new TextEncoder().encode(label)));
}

export const HELD_COLLATERAL = foldDigest('the collateral root this store held');
export const HELD_VALIDITY = foldDigest('the validity document this store held');

/** One family, in the shape the writer is asked for, with the store's own count beside its list. */
export function family(held: readonly string[]): RetentionFamily {
  return { count: held.length, held: held.map((one) => ({ sha256: one, under: { kind: 'root', value: one } })) };
}

/**
 * A manifest of the run, out of this package's own writer: the version one layout where `names` is absent, which
 * states no observation at all, and the version two layout beside it, which names what the store held.
 */
export function artifact(
  at: number,
  names: { readonly collateral: readonly string[]; readonly validity: readonly string[] } | undefined,
): Uint8Array {
  const body = {
    at,
    policy: { maxAgeSeconds: 15_897_600, maxCount: 100_000 },
    retained: { from: at - 100, to: at - 1, count: 42 },
    retired: { byAge: 0, byCount: 0, trims: [] },
    chain: { anchor: foldDigest(`store/anchor/${String(at)}`), head: foldDigest(`store/head/${String(at)}`) },
    duty: { article: '19(1)' as const, requiredSeconds: 100, heldSeconds: 100, met: true },
  };
  return retentionDocumentBytes(
    names === undefined
      ? { v: 1, ...body }
      : { v: 2, ...body, presence: { collateral: family(names.collateral), validity: family(names.validity) } },
  );
}

/** The three summaries, folded here rather than trusted from the reader, so a drift is a disagreement. */
function summariesOf(packs: readonly EpochInventoryPack[]): Pick<EpochInventoryManifest, 'window' | 'chain' | 'duty'> {
  const ordered = [...packs].sort((a, b) => a.span.from - b.span.from || a.at - b.at || (a.sha256 < b.sha256 ? -1 : 1));
  const breaks: Array<{ file: string; afterHead: string; anchor: string }> = [];
  for (let index = 1; index < ordered.length; index += 1) {
    const one = ordered[index];
    const before = ordered[index - 1];
    if (one !== undefined && before !== undefined && one.chain.anchor !== before.chain.head) {
      breaks.push({ file: one.file, afterHead: before.chain.head, anchor: one.chain.anchor });
    }
  }
  const short = ordered
    .filter((one) => one.duty.held < one.duty.required)
    .map((one) => ({
      file: one.file,
      art: one.duty.art,
      required: one.duty.required,
      held: one.duty.held,
      shortBy: one.duty.required - one.duty.held,
    }));
  const first = ordered[0];
  const last = ordered[ordered.length - 1];
  if (first === undefined || last === undefined) throw new Error('a run of no packs states no window to fold');
  return {
    window: { from: first.span.from, to: last.span.to },
    chain: { anchor: first.chain.anchor, head: last.chain.head, continuous: breaks.length === 0, breaks },
    duty: { carried: short.length === 0, short },
  };
}

/**
 * A run of `count` windows that continues itself, each entry sealing one manifest, and those manifests in the
 * same order beside it. `names` answers for one entry: what its store reported holding, or nothing at all for the
 * entry whose manifest is of the layout that states no presence. `over` moves one entry after it is built, which
 * is how the cases that state one digest twice are made without touching anything else.
 */
export function buildRun(
  count: number,
  names: (index: number) => { collateral: readonly string[]; validity: readonly string[] } | undefined,
  over: (index: number, pack: EpochInventoryPack) => EpochInventoryPack = (_, one) => one,
): { manifest: EpochInventoryManifest; artifacts: Uint8Array[] } {
  const packs: EpochInventoryPack[] = [];
  const artifacts: Uint8Array[] = [];
  let anchor = foldDigest('the seam a retirement left');
  for (let index = 0; index < count; index += 1) {
    const from = FOLD_RUN_START + index * FOLD_WINDOW;
    const to = FOLD_RUN_START + (index + 1) * FOLD_WINDOW;
    const bytes = artifact(to + 10, names(index));
    artifacts.push(bytes);
    const sha = foldDigest(`pack/${String(index)}`);
    const home = `packs/${sha}`;
    const pack = over(index, {
      file: `${home}/pack-v1.cbor`,
      retention: `${home}/retention-v1.json`,
      sha256: sha,
      retentionSha256: toHex(sha256(bytes)),
      at: to + 10,
      span: { from, to },
      items: 3,
      chain: { anchor, head: foldDigest(`head/${String(index)}`) },
      kid: foldDigest(`kid/${String(index)}`),
      duty: { art: '19(1)', rev: from - DAY, required: 100, held: 200 },
    });
    packs.push(pack);
    anchor = pack.chain.head;
  }
  return {
    manifest: {
      v: 1,
      epoch: 'presence-fold',
      manifest: { iss: 'dpl-fold', ins: 'cvm-fold', epk: 1 },
      packs,
      ...summariesOf(packs),
    },
    artifacts,
  };
}

/** The run every case starts from: three windows, each entry naming the same collateral root and validity document. */
export const HELD = () => ({ collateral: [HELD_COLLATERAL], validity: [HELD_VALIDITY] });
export const FOLD_HONEST = buildRun(3, HELD);

/** The fold's gap: a run whose middle entry names only the validity document, so the root goes unstated inside it. */
export const FOLD_GAP = buildRun(3, (index) => (index === 1 ? { collateral: [], validity: [HELD_VALIDITY] } : HELD()));

/** The fold's short run: the first entry's manifest is of the layout that states no observation at all. */
export const FOLD_LATE = buildRun(3, (index) => (index === 0 ? undefined : HELD()));

/** An honest document through the writer, which runs the same fold over the same artifacts before it signs. */
export function sealOf(one: { manifest: EpochInventoryManifest; artifacts: readonly Uint8Array[] }): Uint8Array {
  return signEpochInventory(one.manifest, FOLD_KEY, one.artifacts);
}

/**
 * A document assembled from the published pieces rather than through the writer, for the cases the writer refuses
 * to sign: the manifest as built, sealed under the key every case here names.
 */
export function sealFoldDocument(manifest: EpochInventoryManifest): Uint8Array {
  const payloadBytes = encodeEpochInventoryManifest(manifest);
  const header = encodeEpochInventoryProtectedHeader(FOLD_KEY.kid);
  return sealEpochInventory(
    header,
    payloadBytes,
    ed25519.sign(epochInventorySigStructure(header, payloadBytes), FOLD_KEY.privateKey),
  );
}

/** The designation a fold case hands: the honest key, and the manifests beside it where the case has any. */
export function foldReadWith(presence?: readonly Uint8Array[]): EpochInventoryVerifyOptions {
  return { publicKey: FOLD_KEY.publicKey, ...(presence === undefined ? {} : { presence }) };
}

/** The code a call answered with, and the sentence it gave, in one shape for the cases to compare. */
export function foldRefusal(run: () => unknown): { code: string; message: string } {
  try {
    run();
  } catch (err) {
    if (err instanceof ReceiptError) return { code: err.code, message: err.message };
    return { code: `UNCODED ${String(err)}`, message: String(err) };
  }
  return { code: 'accepted', message: '' };
}
