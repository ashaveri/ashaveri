import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { fromBase64Url, toHex, verifyReceipt } from '@ashaveri/receipt';

// Dynamic loading avoids a gateway-to-SDK build cycle; these are test-only contracts.
interface ManifestReader {
  readDeploymentManifest(bytes: Uint8Array, policy?: { manifestKeys: Readonly<Record<string, string>> }): {
    manifest: ParsedManifest;
    authentication: ManifestAuthentication;
  };
  adjudicateReceiptEpoch(manifest: ParsedManifest, claim: { kid: string; epoch: number; issuedAt: number }):
    | EpochAccepted
    | { ok: false; code: 'MANIFEST_EPOCH_UNDECLARED' | 'MANIFEST_EPOCH_DISAGREES'; detail: string };
}
interface ParsedManifest {
  iss: string;
  ins: string;
  keys: readonly { kid: string; alg: 'Ed25519'; publicKey: string }[];
}
export interface ManifestAuthentication {
  readonly sealed: boolean;
  readonly authenticated: boolean;
  readonly kid: string | null;
  readonly demanded: boolean;
  readonly advisory: string | null;
}
interface EpochAccepted {
  readonly ok: true;
  readonly basis: 'windows' | 'current-epoch';
  readonly epoch: number;
  readonly kid: string;
  readonly validFrom: number | null;
  readonly validTo: number | null;
  readonly superseded: boolean;
  readonly detail: string;
}
const client = (await import(new URL('../../../packages/sdk/dist/index.js', import.meta.url).href)) as ManifestReader;

export const HEAD_PIN_DOCUMENT = 'checkpoint-head-pin';
export interface PinnedHead {
  readonly sequence: number;
  readonly sha256: string;
}
export interface PinKey {
  readonly keyId: string;
  readonly publicKey: string;
}
export interface PinKeyPair extends PinKey {
  readonly privateKey: string;
}
export type HeadPinRefusalCode =
  | 'PIN_SELF_ISSUED' | 'PIN_SCOPE_MISMATCH' | 'PIN_SIGNATURE_INVALID' | 'PIN_FORM'
  | 'PIN_HOLDER_MISMATCH' | 'PIN_EVIDENCE';

export class HeadPinError extends Error {
  readonly code: HeadPinRefusalCode;
  constructor(code: HeadPinRefusalCode, detail: string) {
    super(`${code}: ${detail}`);
    this.name = 'HeadPinError';
    this.code = code;
  }
}
export interface HeadPin {
  readonly document: typeof HEAD_PIN_DOCUMENT;
  readonly head: PinnedHead;
  readonly scope: string;
  readonly signer: PinKey;
  readonly signature: string;
}
export interface BootCapture {
  readonly boot: string;
  readonly manifest: Uint8Array;
  readonly receipts: readonly { readonly id: string; readonly bytes: Uint8Array }[];
}
export interface BootLedger {
  readonly boot: string;
  readonly manifestSha256: string;
  readonly receipts: readonly { readonly id: string; readonly sha256: string }[];
}
export type ManifestTrust =
  | { readonly mode: 'synthetic-tofu' }
  | { readonly mode: 'designated-keys'; readonly manifestKeys: Readonly<Record<string, string>> };
export interface PinEvidence {
  readonly issuanceIdentities: readonly string[];
  readonly boots: readonly {
    readonly boot: string;
    readonly authentication: ManifestAuthentication;
    readonly receipts: readonly { readonly id: string; readonly sha256: string; readonly epoch: EpochAccepted }[];
  }[];
}

// Only frozen results from the evidence reader can authorize a pin check.
const validated = new WeakSet<PinEvidence>();
const digest = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

export function retainBootCapture(capture: BootCapture): BootLedger {
  return Object.freeze({
    boot: capture.boot,
    manifestSha256: digest(capture.manifest),
    receipts: Object.freeze(capture.receipts.map((receipt) => Object.freeze({ id: receipt.id, sha256: digest(receipt.bytes) }))),
  });
}

function evidenceAssert(condition: unknown, detail: string): asserts condition {
  if (!condition) throw new HeadPinError('PIN_EVIDENCE', detail);
}

export function readPinEvidence(context: {
  readonly ledger: readonly BootLedger[];
  readonly captures: readonly BootCapture[];
  readonly trust: ManifestTrust;
}): PinEvidence {
  evidenceAssert(context && Array.isArray(context.ledger as unknown) && Array.isArray(context.captures as unknown), 'the original ledger and candidate captures are required');
  const { ledger, captures, trust } = context;
  evidenceAssert(trust?.mode === 'synthetic-tofu' || trust?.mode === 'designated-keys', 'explicit manifest trust mode is required');
  if (trust.mode === 'designated-keys') {
    evidenceAssert(trust.manifestKeys && Object.keys(trust.manifestKeys).length > 0, 'designated-key mode requires at least one manifest key');
  }
  const originalBoots = new Set(ledger.map((boot) => boot.boot));
  const candidateBoots = new Set(captures.map((boot) => boot.boot));
  evidenceAssert(originalBoots.size === ledger.length && candidateBoots.size === captures.length && captures.length === ledger.length,
    'boot coverage must be exact and duplicate-free');
  const acknowledged = ledger.flatMap((boot) => boot.receipts.map((receipt) => receipt.id));
  evidenceAssert(new Set(acknowledged).size === acknowledged.length, 'the original ledger repeats an acknowledgement');
  const issuance = new Set<string>();
  const boots = ledger.map((original) => {
    const capture = captures.find((candidate) => candidate.boot === original.boot);
    evidenceAssert(capture !== undefined, `missing boot ${original.boot}`);
    evidenceAssert(digest(capture.manifest) === original.manifestSha256, `manifest bytes changed for ${original.boot}`);
    const ids = capture.receipts.map((receipt) => receipt.id);
    evidenceAssert(ids.length === original.receipts.length && new Set(ids).size === ids.length, `receipt coverage differs for ${original.boot}`);
    for (const receipt of original.receipts) {
      const candidate = capture.receipts.find((each) => each.id === receipt.id);
      evidenceAssert(candidate !== undefined && digest(candidate.bytes) === receipt.sha256, `missing or changed receipt ${receipt.id}`);
    }
    const { manifest, authentication } = client.readDeploymentManifest(capture.manifest,
      trust.mode === 'designated-keys' ? { manifestKeys: trust.manifestKeys } : undefined);
    const keys = new Map<string, Uint8Array>();
    for (const key of manifest.keys) {
      const raw = fromBase64Url(key.publicKey);
      evidenceAssert(digest(raw) === key.kid, `manifest kid/public-key mismatch in ${original.boot}`);
      keys.set(key.kid, raw);
      issuance.add(key.kid);
    }
    const receipts = capture.receipts.map((receipt) => {
      const verified = verifyReceipt(receipt.bytes, { resolveKey: (kid) => keys.get(toHex(kid)) });
      evidenceAssert(verified.payload.iss === manifest.iss && verified.payload.ins === manifest.ins,
        `receipt issuer/instance disagrees with boot ${original.boot}`);
      const epoch = client.adjudicateReceiptEpoch(manifest, {
        kid: toHex(verified.header.kid), epoch: verified.payload.epk, issuedAt: verified.payload.iat,
      });
      evidenceAssert(epoch.ok, epoch.ok ? '' : `${epoch.code}: ${epoch.detail}`);
      return Object.freeze({ id: receipt.id, sha256: digest(receipt.bytes), epoch: Object.freeze(epoch) });
    });
    return Object.freeze({ boot: original.boot, authentication: Object.freeze(authentication), receipts: Object.freeze(receipts) });
  });
  const result = Object.freeze({ issuanceIdentities: Object.freeze([...issuance]), boots: Object.freeze(boots) });
  validated.add(result);
  return result;
}

function pinBody(pin: Omit<HeadPin, 'signature'>): Buffer {
  return Buffer.from(`${pin.document}|${pin.scope}|${pin.signer.keyId}|${pin.signer.publicKey}|${pin.head.sequence}|${pin.head.sha256}`, 'utf8');
}

export function pinKeyId(publicKey: string): string {
  let key;
  try {
    key = createPublicKey(publicKey);
  } catch {
    throw new HeadPinError('PIN_FORM', 'invalid public key');
  }
  if (key.asymmetricKeyType !== 'ed25519') throw new HeadPinError('PIN_FORM', 'a pin requires Ed25519');
  const jwk = key.export({ format: 'jwk' });
  return digest(Buffer.from(jwk.x!, 'base64url'));
}

export function pinPublicKeyOfRaw(publicKeyBase64Url: string): string {
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(publicKeyBase64Url, 'base64url')]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' }).export({ type: 'spki', format: 'pem' }).toString();
}

export function generatePinKeyPair(): PinKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  return { keyId: pinKeyId(publicPem), publicKey: publicPem, privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };
}

export function canonicalDigest(value: unknown): string {
  return createHash('sha256').update(stableJson(value), 'utf8').digest('hex');
}
function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (typeof value === 'object' && value !== null) {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, each]) => each !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, each]) => `${JSON.stringify(key)}:${stableJson(each)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function signHeadPin(input: { key: PinKeyPair; head: PinnedHead; scope: string }): HeadPin {
  const rest: Omit<HeadPin, 'signature'> = {
    document: HEAD_PIN_DOCUMENT,
    head: { sequence: input.head.sequence, sha256: input.head.sha256 },
    scope: input.scope,
    signer: { keyId: input.key.keyId, publicKey: input.key.publicKey },
  };
  return { ...rest, signature: sign(null, pinBody(rest), createPrivateKey(input.key.privateKey)).toString('hex') };
}

export function verifyHeadPin(pin: HeadPin, demands: {
  readonly scope: string;
  readonly expectedHolder: PinKey;
  readonly evidence: PinEvidence;
}): { readonly head: PinnedHead; readonly evidence: PinEvidence } {
  assertForm(pin);
  const signerId = pinKeyId(pin.signer.publicKey);
  if (signerId !== pin.signer.keyId) throw new HeadPinError('PIN_FORM', 'the signer id disagrees with its public key');
  const holder = demands?.expectedHolder;
  if (!holder || holder.keyId !== signerId || pinKeyId(holder.publicKey) !== signerId) {
    throw new HeadPinError('PIN_HOLDER_MISMATCH', 'the signer is not the externally expected holder');
  }
  const evidence = demands.evidence;
  evidenceAssert(evidence && validated.has(evidence) && evidence.boots.some((boot) => boot.receipts.length > 0),
    'validated nonempty capture evidence is required');
  if (evidence.issuanceIdentities.includes(signerId)) {
    throw new HeadPinError('PIN_SELF_ISSUED', `${signerId} is a receipt issuer in the retained capture ledger`);
  }
  if (pin.scope !== demands.scope) throw new HeadPinError('PIN_SCOPE_MISMATCH', 'the pin names a different declaration');
  if (!verify(null, pinBody(pin), createPublicKey(pin.signer.publicKey), Buffer.from(pin.signature, 'hex'))) {
    throw new HeadPinError('PIN_SIGNATURE_INVALID', 'the pin signature does not verify');
  }
  return { head: Object.freeze({ ...pin.head }), evidence };
}

function assertForm(pin: HeadPin): void {
  if (!pin || pin.document !== HEAD_PIN_DOCUMENT || !pin.head || !pin.signer ||
    !Number.isSafeInteger(pin.head.sequence) || pin.head.sequence < 0 ||
    typeof pin.head.sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(pin.head.sha256) ||
    typeof pin.scope !== 'string' || !/^[0-9a-f]{64}$/u.test(pin.scope) ||
    typeof pin.signature !== 'string' || !/^[0-9a-f]{128}$/u.test(pin.signature) ||
    typeof pin.signer.publicKey !== 'string' || typeof pin.signer.keyId !== 'string') {
    throw new HeadPinError('PIN_FORM', 'malformed synthetic head pin');
  }
}
