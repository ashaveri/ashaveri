import { MEASUREMENT_BYTES, isTeeKind, type TeeKind } from '@ashaveri/receipt';

export type { TeeKind };

export interface ManifestKey {
  readonly kid: string;
  readonly alg: 'Ed25519';
  readonly publicKey: string;
  /**
   * The signing-key epoch this key produced, and the first instant (unix seconds) at which the
   * deployment accepts a signature from it. Both or neither: an entry naming one and not the other is
   * a manifest that began declaring windows and stopped halfway, which reads as an epoch that never
   * ends, so `parseManifest` refuses it rather than choosing a bound.
   *
   * Neither is what every manifest published before epochs were checked carries, and that state is
   * reported as `epochs: null` below rather than as a window with invented ends.
   */
  readonly epk?: number;
  readonly validFrom?: number;
}

/**
 * One epoch a manifest declares: the keys that signed under it, and the half-open window in which a
 * signature from it is accepted.
 *
 * The upper bound is never written down, because two members that must agree with each other are two
 * chances to publish a gap and an overlap. It is the start of the next epoch up, and null for the
 * highest epoch published, which has no end published yet. Without the bound the retention of a
 * superseded key would be open-ended, and a holder of a retired key could keep signing fresh
 * receipts that read as though they came from before the rotation.
 */
export interface DeclaredEpoch {
  readonly epoch: number;
  readonly validFrom: number;
  readonly validTo: number | null;
  readonly kids: readonly string[];
}

export interface ManifestModel {
  readonly id: string;
  readonly wts: string;
}

export interface DeploymentManifest {
  readonly v: 1;
  readonly iss: string;
  readonly ins: string;
  readonly epk: number;
  readonly keys: readonly ManifestKey[];
  /**
   * The declared rotation history, ascending by epoch, or null when no key entry names an epoch.
   *
   * Null is not an empty list, and the difference carries the whole of the trust story: an empty list
   * would be a deployment that declared no acceptable epoch, and null is a deployment that was started
   * before anyone could declare one. A reader answers `null` with the one fact such a manifest does
   * state, that the keys it lists are the keys of its current epoch.
   */
  readonly epochs: readonly DeclaredEpoch[] | null;
  readonly models: readonly ManifestModel[];
  readonly meas: { readonly tee: TeeKind; readonly m: string };
}

const HEX_64 = /^[0-9a-f]{64}$/;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;
const HEX_MEASUREMENT = Object.fromEntries(
  Object.entries(MEASUREMENT_BYTES).map(([kind, bytes]) => [kind, new RegExp(`^[0-9a-f]{${bytes * 2}}$`)]),
) as Record<TeeKind, RegExp>;

export function parseManifest(value: unknown): DeploymentManifest {
  const bad = (detail: string): Error => new Error(`deployment manifest is invalid: ${detail}`);
  if (typeof value !== 'object' || value === null) throw bad('not an object');
  const raw = value as Record<string, unknown>;
  if (raw['v'] !== 1) throw bad('v must be 1');
  const iss = raw['iss'];
  if (typeof iss !== 'string' || iss.length === 0) throw bad('iss must be a non-empty string');
  const ins = raw['ins'];
  if (typeof ins !== 'string' || ins.length === 0) throw bad('ins must be a non-empty string');
  const epk = raw['epk'];
  if (typeof epk !== 'number' || !Number.isSafeInteger(epk) || epk < 0) throw bad('epk must be a non-negative integer');
  const keysRaw = raw['keys'];
  if (!Array.isArray(keysRaw) || keysRaw.length === 0) throw bad('keys must be a non-empty array');
  const keys: ManifestKey[] = [];
  // Which of the two shapes this array has, decided by the first entry that says: an entry either
  // names an epoch and a start or names neither, and a manifest whose entries disagree is refused
  // rather than read as one whose undeclared keys are live forever.
  let declared: boolean | null = null;
  const windows = new Map<number, { validFrom: number; kids: string[] }>();
  for (const entry of keysRaw) {
    if (typeof entry !== 'object' || entry === null) throw bad('each key must be an object');
    const raw = entry as Record<string, unknown>;
    const kid = raw['kid'];
    const alg = raw['alg'];
    const publicKey = raw['publicKey'];
    if (typeof kid !== 'string' || !HEX_64.test(kid)) throw bad('key kid must be 64 hex characters');
    if (alg !== 'Ed25519') throw bad('key alg must be Ed25519');
    if (typeof publicKey !== 'string' || !BASE64URL_32.test(publicKey)) {
      throw bad('key publicKey must be base64url-encoded 32 bytes');
    }
    const entryEpoch = raw['epk'];
    const entryStart = raw['validFrom'];
    if ((entryEpoch === undefined) !== (entryStart === undefined)) {
      throw bad(
        `key ${kid} declares ${entryEpoch === undefined ? 'a validity start without an epoch' : 'an epoch without a validity start'}, and one member of the pair states nothing a reader can use`,
      );
    }
    if (entryEpoch === undefined) {
      if (declared === true) throw bad(`key ${kid} names no epoch while another key in the same manifest names one`);
      declared ??= false;
      keys.push({ kid, alg, publicKey });
      continue;
    }
    if (typeof entryEpoch !== 'number' || !Number.isSafeInteger(entryEpoch) || entryEpoch < 0) {
      throw bad(`key ${kid} epk must be a non-negative integer`);
    }
    if (typeof entryStart !== 'number' || !Number.isSafeInteger(entryStart) || entryStart < 0) {
      throw bad(`key ${kid} validFrom must be a non-negative integer of unix seconds`);
    }
    if (declared === false) throw bad(`key ${kid} names an epoch while another key in the same manifest names none`);
    declared = true;
    const held = windows.get(entryEpoch);
    if (held === undefined) {
      windows.set(entryEpoch, { validFrom: entryStart, kids: [kid] });
    } else {
      if (held.validFrom !== entryStart) {
        throw bad(`epoch ${entryEpoch} is declared with two validity starts, ${held.validFrom} and ${entryStart}`);
      }
      if (!held.kids.includes(kid)) held.kids.push(kid);
    }
    keys.push({ kid, alg, publicKey, epk: entryEpoch, validFrom: entryStart });
  }
  const epochs = declared === true ? orderedWindows(windows) : null;
  const modelsRaw = raw['models'];
  if (!Array.isArray(modelsRaw)) throw bad('models must be an array');
  const models: ManifestModel[] = [];
  for (const entry of modelsRaw) {
    if (typeof entry !== 'object' || entry === null) throw bad('each model must be an object');
    const id = (entry as Record<string, unknown>)['id'];
    const wts = (entry as Record<string, unknown>)['wts'];
    if (typeof id !== 'string' || id.length === 0) throw bad('model id must be a non-empty string');
    if (typeof wts !== 'string' || !HEX_64.test(wts)) throw bad('model wts must be 64 hex characters');
    models.push({ id, wts });
  }
  const measRaw = raw['meas'];
  if (typeof measRaw !== 'object' || measRaw === null) throw bad('meas must be an object');
  const tee = (measRaw as Record<string, unknown>)['tee'];
  const m = (measRaw as Record<string, unknown>)['m'];
  if (!isTeeKind(tee)) {
    throw bad('meas.tee is not a known environment kind');
  }
  const hexChars = MEASUREMENT_BYTES[tee] * 2;
  if (typeof m !== 'string' || !HEX_MEASUREMENT[tee].test(m)) {
    throw bad(`meas.m must be ${hexChars} hex characters for tee '${tee}'`);
  }
  return { v: 1, iss, ins, epk, keys, epochs, models, meas: { tee, m } };
}

/**
 * The declared windows in the order a reader walks them, each one ending where the next begins.
 *
 * Ascending epochs with strictly ascending starts is a rule the manifest has to hold rather than a
 * preference, because the bound of a retained key comes out of the entry beside it: a deployment that
 * published epoch 4 as starting before epoch 3 would give a reader two windows containing now, and
 * the key a receipt is verified under would depend on which of the two the reader happened to reach
 * first. Refusing the pair here is what keeps `validTo` a fact of the document instead of an artefact
 * of a loop.
 */
function orderedWindows(windows: Map<number, { validFrom: number; kids: string[] }>): DeclaredEpoch[] {
  const ascending = [...windows.entries()].sort((a, b) => a[0] - b[0]);
  const built: Array<{ epoch: number; validFrom: number; validTo: number | null; kids: readonly string[] }> = [];
  for (const [epoch, held] of ascending) {
    const previous = built[built.length - 1];
    if (previous !== undefined) {
      if (held.validFrom <= previous.validFrom) {
        throw new Error(
          `deployment manifest is invalid: epoch ${epoch} starts at ${held.validFrom}, which is not after epoch ${previous.epoch} at ${previous.validFrom}, so a signature stamped between the two belongs to no single key`,
        );
      }
      previous.validTo = held.validFrom;
    }
    built.push({ epoch, validFrom: held.validFrom, validTo: null, kids: held.kids });
  }
  return built.map((entry) => ({ ...entry }));
}
