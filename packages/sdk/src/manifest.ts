export type TeeKind = 'snp' | 'snp+h100cc' | 'tdx';

export interface ManifestKey {
  readonly kid: string;
  readonly alg: 'Ed25519';
  readonly publicKey: string;
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
  readonly models: readonly ManifestModel[];
  readonly meas: { readonly tee: TeeKind; readonly m: string };
}

const TEE_KINDS: readonly TeeKind[] = ['snp', 'snp+h100cc', 'tdx'];
const HEX_64 = /^[0-9a-f]{64}$/;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;

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
  for (const entry of keysRaw) {
    if (typeof entry !== 'object' || entry === null) throw bad('each key must be an object');
    const kid = (entry as Record<string, unknown>)['kid'];
    const alg = (entry as Record<string, unknown>)['alg'];
    const publicKey = (entry as Record<string, unknown>)['publicKey'];
    if (typeof kid !== 'string' || !HEX_64.test(kid)) throw bad('key kid must be 64 hex characters');
    if (alg !== 'Ed25519') throw bad('key alg must be Ed25519');
    if (typeof publicKey !== 'string' || !BASE64URL_32.test(publicKey)) {
      throw bad('key publicKey must be base64url-encoded 32 bytes');
    }
    keys.push({ kid, alg, publicKey });
  }
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
  if (typeof tee !== 'string' || !TEE_KINDS.includes(tee as TeeKind)) {
    throw bad('meas.tee is not a known TEE kind');
  }
  if (typeof m !== 'string' || !HEX_64.test(m)) throw bad('meas.m must be 64 hex characters');
  return { v: 1, iss, ins, epk, keys, models, meas: { tee: tee as TeeKind, m } };
}
