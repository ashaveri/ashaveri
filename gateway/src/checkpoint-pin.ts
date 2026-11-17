import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';

/**
 * A head pin: one party's signature over the chain head another party's store states.
 *
 * The rule the module exists for is the independence check, and it runs on key identity before any
 * signature is looked at. A pin signed by a key that also issues the head it names witnesses nothing,
 * because whoever held the issuing key could write both halves of the claim, so it is refused whether or
 * not its signature is good. The order is the control: a verifier that checked the signature first would
 * have believed the claim before it noticed who made it.
 *
 * This is gateway-local. The document below names itself `checkpoint-head-pin` and appears in no published
 * schema and no vector family, so nothing outside this package reads these bytes as an evidence format.
 */

/** The document name a pin carries, so a refusal can name what it was asked to read. */
export const HEAD_PIN_DOCUMENT = 'checkpoint-head-pin';

/** The head one store states, in the store's own units: a chain position and the digest at it. */
export interface PinnedHead {
  readonly sequence: number;
  readonly sha256: string;
}

/** A key a pin is signed with: the public half and the identity the independence check weighs. */
export interface PinKey {
  readonly keyId: string;
  /** The public half, as a PEM SPKI document. */
  readonly publicKey: string;
}

/** A key pair for the pinning act. The private half is the thing a holder is supposed to keep apart. */
export interface PinKeyPair extends PinKey {
  /** The private half, as a PEM PKCS#8 document. Held by the pinner and never by the verifier. */
  readonly privateKey: string;
}

/** Why a pin was refused, in the two states a caller has to tell apart. */
export type HeadPinRefusalCode = 'PIN_SELF_ISSUED' | 'PIN_SCOPE_MISMATCH' | 'PIN_SIGNATURE_INVALID' | 'PIN_FORM';

export class HeadPinError extends Error {
  readonly code: HeadPinRefusalCode;

  constructor(code: HeadPinRefusalCode, detail: string) {
    super(`${code}: ${detail}`);
    this.name = 'HeadPinError';
    this.code = code;
  }
}

/** A signature over one head and one scope, naming the key that made it. */
export interface HeadPin {
  readonly document: typeof HEAD_PIN_DOCUMENT;
  readonly head: PinnedHead;
  /** The digest of the declared scope the pinner was looking at, so a pin cannot be moved between scopes. */
  readonly scope: string;
  readonly signer: PinKey;
  readonly signature: string;
}

/** The bytes a signature covers: every member that states what was pinned, in a fixed order. */
function pinBody(pin: Omit<HeadPin, 'signature'>): Buffer {
  return Buffer.from(
    `${pin.document}|${pin.scope}|${pin.signer.keyId}|${pin.signer.publicKey}|${pin.head.sequence}|${pin.head.sha256}`,
    'utf8',
  );
}

/**
 * The identity of an Ed25519 public key: the digest of the raw key bytes.
 *
 * It is derived rather than declared, so a pin cannot name whatever key id it liked: the identity a
 * refusal compares is computed from the bytes the signer handed over. It is taken over the raw key and
 * not over one encoding of it, because the same key reaches a reader as a PEM document here and as the
 * base64url member of a deployment manifest there, and two derivations that disagree would be two answers
 * to whether a pin is independent.
 */
export function pinKeyId(publicKey: string): string {
  const jwk = createPublicKey(publicKey).export({ format: 'jwk' }) as { x?: string };
  if (typeof jwk.x !== 'string') {
    throw new HeadPinError('PIN_FORM', 'the key handed over is not an Ed25519 key this reader can name');
  }
  return rawPinKeyId(jwk.x);
}

/** The identity of a raw Ed25519 public key, given as base64url, which is how a manifest publishes one. */
export function rawPinKeyId(publicKeyBase64Url: string): string {
  return createHash('sha256').update(Buffer.from(publicKeyBase64Url, 'base64url')).digest('hex');
}

/**
 * The PEM a raw Ed25519 public key corresponds to, so a verifier can weigh a key a manifest published.
 *
 * A deployment publishes the raw 32 bytes; a signature is checked against a key object, and the two have to
 * name one key. A reader that could not make that step could not ask whether a pin came from the key the
 * deployment says signs its receipts.
 */
export function pinPublicKeyOfRaw(publicKeyBase64Url: string): string {
  const der = Buffer.from(`302a300506032b6570032100${Buffer.from(publicKeyBase64Url, 'base64url').toString('hex')}`, 'hex');
  return createPublicKey({ key: der, format: 'der', type: 'spki' }).export({ type: 'spki', format: 'pem' }).toString();
}

/** A fresh pinning key. Callers generate it where the issuance keys cannot reach it. */
export function generatePinKeyPair(): PinKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  return { keyId: pinKeyId(publicPem), publicKey: publicPem, privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };
}

/** The key pair a caller already holds the private half of, as the pair type this module answers with. */
export function pinKeyPairOf(privateKeyPem: string): PinKeyPair {
  const publicKey = createPublicKey(createPrivateKey(privateKeyPem)).export({ type: 'spki', format: 'pem' }).toString();
  return { keyId: pinKeyId(publicKey), publicKey, privateKey: privateKeyPem };
}

/** A canonical digest of a declared scope, so two callers over one scope compute one value. */
export function canonicalDigest(value: unknown): string {
  return createHash('sha256').update(stableJson(value), 'utf8').digest('hex');
}

/** JSON with every object's members in name order, which is what makes a digest repeatable. */
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

/** Sign one head under one scope. The scope digest is the pinner's, not the store's. */
export function signHeadPin(input: { key: PinKeyPair; head: PinnedHead; scope: string }): HeadPin {
  const rest: Omit<HeadPin, 'signature'> = {
    document: HEAD_PIN_DOCUMENT,
    head: { sequence: input.head.sequence, sha256: input.head.sha256 },
    scope: input.scope,
    signer: { keyId: input.key.keyId, publicKey: input.key.publicKey },
  };
  return { ...rest, signature: sign(null, pinBody(rest), createPrivateKey(input.key.privateKey)).toString('hex') };
}

/**
 * Reads a pin back, or refuses it.
 *
 * `demands.issuedBy` is the identity set of the keys that issue the heads this pin could be naming, which
 * for a running deployment is the key list its own published document carries. A pin whose signer is in
 * that set is refused at the identity step, and its signature is never reached.
 */
export function verifyHeadPin(
  pin: HeadPin,
  demands: { readonly issuedBy: readonly string[]; readonly scope: string },
): PinnedHead {
  assertForm(pin);
  const signerId = pinKeyId(pin.signer.publicKey);
  if (signerId !== pin.signer.keyId) {
    throw new HeadPinError('PIN_FORM', `the pin states key id ${pin.signer.keyId} and its public key digests to ${signerId}`);
  }
  if (demands.issuedBy.includes(signerId)) {
    throw new HeadPinError(
      'PIN_SELF_ISSUED',
      `the pin is signed by ${signerId}, which is one of the keys that issues the head it names, so the process that wrote ` +
        'the head also wrote the witness and nothing about this pin is independent of it',
    );
  }
  if (pin.scope !== demands.scope) {
    throw new HeadPinError(
      'PIN_SCOPE_MISMATCH',
      `the pin is over scope ${pin.scope} and this assessment was declared over ${demands.scope}, so the witness names a ` +
        'different declaration than the one it is being offered against',
    );
  }
  const body = pinBody({ document: pin.document, head: pin.head, scope: pin.scope, signer: pin.signer });
  if (!verify(null, body, createPublicKey(pin.signer.publicKey), Buffer.from(pin.signature, 'hex'))) {
    throw new HeadPinError('PIN_SIGNATURE_INVALID', `the signature on the pin over ${pin.head.sha256} does not verify under its own key`);
  }
  return pin.head;
}

/** The shape a pin has to have before any byte of it is weighed. */
function assertForm(pin: HeadPin): void {
  const named = (pin as { readonly document?: unknown }).document;
  if (named !== HEAD_PIN_DOCUMENT) {
    throw new HeadPinError('PIN_FORM', `a pin names document ${String(named)} and this reader reads ${HEAD_PIN_DOCUMENT}`);
  }
  if (!Number.isSafeInteger(pin.head.sequence) || pin.head.sequence < 0) {
    throw new HeadPinError('PIN_FORM', `the pin names chain position ${String(pin.head.sequence)}`);
  }
  if (!/^[0-9a-f]{64}$/.test(pin.head.sha256)) {
    throw new HeadPinError('PIN_FORM', `the pin names head ${pin.head.sha256}, which is not 64 lowercase hex characters`);
  }
  if (!/^[0-9a-f]{128}$/.test(pin.signature)) {
    throw new HeadPinError('PIN_FORM', 'the pin carries a signature that is not 64 bytes of hex');
  }
}
