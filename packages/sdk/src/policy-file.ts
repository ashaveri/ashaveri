import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { sha256 } from '@noble/hashes/sha2.js';
import { MEASUREMENT_BYTES, isTeeKind, type TeeKind } from '@ashaveri/receipt';
import { fromBase64Url, toBase64Url, toHex } from './b64.js';
import { SdkError } from './errors.js';
import type { EvidenceTrustAnchors } from './evidence.js';
import type { AshaveriPolicy } from './policy.js';

/**
 * A verification policy as a file.
 *
 * `AshaveriPolicy` says what a client will accept; this says the same thing in a document a customer
 * can read, diff, sign and hand to an auditor. Two rules make that possible, and they are why the
 * code below is longer than the object it produces.
 *
 * The first is that nothing is dropped. Every key must be one the format defines, and a document
 * that repeats a key is refused, because a reader that kept the second of two values would publish a
 * digest for a policy that is not the one the operator thinks they pinned.
 *
 * The second is that the digest is taken over the loaded policy, canonically re-encoded, and never
 * over the bytes of the file. A formatter, a key reorder and a checkout that rewrites line endings
 * all change bytes without changing what is pinned, and an identity that moves under them is worth
 * nothing to anyone comparing two copies.
 *
 * Vendor root material is the one field that does not fit a JSON string honestly, so it is
 * externalised: the file names a path and the SHA-256 of the bytes there, and the policy digest
 * covers that inner digest rather than any text. Both path and digest are pinned, because leaving
 * either out of the digest would leave a field the operator wrote outside its identity.
 */

/** The only document version this loader reads. */
export const POLICY_FORMAT_VERSION = 1;

/** The prefix every policy digest carries, so a bare hex string cannot be mistaken for one. */
export const POLICY_DIGEST_PREFIX = 'sha256:';

/**
 * Folded into the digest input ahead of the document, so a policy digest is never also the digest of
 * some other structure that happens to serialize the same way.
 */
const DIGEST_DOMAIN = 'ashaveri/policy/v1\0';

/** The families of vendor root a policy can pin, named as `EvidenceTrustAnchors` names them. */
export const ANCHOR_FAMILIES = ['amdArks', 'intelSgxRoots', 'nvidiaRoots'] as const;
export type AnchorFamily = (typeof ANCHOR_FAMILIES)[number];

/** The keys of the document format, listed by the refusal that names an unknown one. */
const FIELDS = [
  'v',
  'issuers',
  'instances',
  'keys',
  'measurements',
  'maxReceiptAgeSeconds',
  'maxEvidenceAgeSeconds',
  'trustAnchors',
] as const;

/** The fields that pin a receipt to something. A policy has to name at least one of them. */
const PIN_FIELDS = ['issuers', 'instances', 'keys', 'measurements'] as const;

const HEX_64 = /^[0-9a-f]{64}$/;
const BASE64URL_32_BYTES = /^[A-Za-z0-9_-]{43}$/;

/**
 * A pattern source, exported so the published schema can be held against the one string this loader
 * actually runs. It refuses the control ranges, the soft hyphen, the zero-width and format
 * characters a terminal hides, the bidi overrides that make a string read differently than it is, the
 * two line separators, and the annotation and interlinear ranges.
 *
 * A pin whose value differs from its appearance is the exact failure this document exists to avoid,
 * so it is refused here rather than escaped on its way to a terminal.
 *
 * Every escape is written as `\uXXXX` rather than `\u{...}`, so the class stays inside the
 * Basic Multilingual Plane. A JSON Schema reader may compile this pattern with or without the
 * regex `u` flag, and `\u{E0020}` without the flag means "a `u`, zero or more times", which would
 * let the two readers disagree about what a policy is allowed to say.
 */
export const PINNED_TEXT_PATTERN =
  '^[^\\u0000-\\u001F\\u007F-\\u009F\\u00AD\\u200B-\\u200F\\u2028\\u2029\\u202A-\\u202E\\u2060-\\u2064\\uFEFF\\uFFF9-\\uFFFB]+$';
const PINNED_TEXT = new RegExp(PINNED_TEXT_PATTERN, 'u');

/** One vendor root, externalised: where it is, and what is there. */
export interface PolicyTrustAnchor {
  readonly path: string;
  readonly sha256: string;
}

/**
 * The roots of one vendor. `null` means the verifier's bundled root for that family, which is the
 * default `AshaveriPolicy.trustAnchors` documents. An empty list is the opposite: trust nothing in
 * this family, and refuse any evidence that claims it.
 */
export type PolicyAnchorFamily = readonly PolicyTrustAnchor[] | null;

export interface PolicyFileTrustAnchors {
  readonly amdArks: PolicyAnchorFamily;
  readonly intelSgxRoots: PolicyAnchorFamily;
  readonly nvidiaRoots: PolicyAnchorFamily;
}

/**
 * The document form in its normalised spelling: sets sorted, defaults written out, paths with
 * forward slashes. A pin collection is either present or absent, because `null`, `{}` and `[]` are
 * all one accident with different text; the two age windows and the three anchor families do accept
 * an explicit `null`, which is how a document says it considered them and took the default.
 */
export interface PolicyFile {
  readonly v: number;
  readonly issuers?: readonly string[];
  readonly instances?: readonly string[];
  readonly keys?: Readonly<Record<string, string>>;
  readonly measurements?: Readonly<Record<string, readonly string[]>>;
  readonly maxReceiptAgeSeconds: number | null;
  readonly maxEvidenceAgeSeconds: number | null;
  readonly trustAnchors: PolicyFileTrustAnchors;
}

export interface LoadedPolicyAnchor {
  readonly family: AnchorFamily;
  readonly path: string;
  readonly sha256: string;
}

export interface LoadedPolicy {
  /** The document as read, in its normalised spelling. */
  readonly file: PolicyFile;
  /** The policy the document names, ready to hand to `verifyCompletionReceipt`. */
  readonly policy: AshaveriPolicy;
  /** The digest of that policy: `sha256:` and 64 hex, over the canonical re-encoding. */
  readonly digest: string;
  /** The vendor roots read off disk, in the order the document lists them. */
  readonly anchors: readonly LoadedPolicyAnchor[];
}

function invalid(detail: string): SdkError {
  return new SdkError('POLICY_FILE_INVALID', `policy file ${detail}`);
}

function emptyPin(label: string): SdkError {
  return new SdkError(
    'POLICY_EMPTY_PIN',
    `policy file ${label} is an empty list, which pins nothing: name at least one value, or leave the field out`,
  );
}

function spelled(value: unknown): string {
  return value === undefined ? 'absent' : JSON.stringify(value);
}

/**
 * A JSON reader that refuses a repeated key.
 *
 * `JSON.parse` keeps the last of two values and says nothing, which is the silent drop this loader
 * cannot afford: the document is the thing a digest gets published for, and whoever wrote both lines
 * meant one of them. Leaf values still go through `JSON.parse`, so numbers and escapes carry exactly
 * the semantics the platform gives them.
 */
function scanJson(text: string): unknown {
  let index = text.charCodeAt(0) === 0xfeff ? 1 : 0;

  const position = (): string => {
    let line = 1;
    let column = 1;
    for (let at = 0; at < index; at += 1) {
      if (text.charCodeAt(at) === 0x0a) {
        line += 1;
        column = 1;
      } else {
        column += 1;
      }
    }
    return `line ${line}, column ${column}`;
  };

  const fail = (detail: string): never => {
    throw invalid(`is not one JSON document: ${detail} (${position()})`);
  };

  const skipSpace = (): void => {
    while (index < text.length) {
      const code = text.charCodeAt(index);
      if (code !== 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) break;
      index += 1;
    }
  };

  const peek = (): string => (index < text.length ? (text[index] as string) : '');

  const word = (text2: string, value: unknown): unknown => {
    if (text.startsWith(text2, index)) {
      index += text2.length;
      return value;
    }
    return fail('expected a value');
  };

  function parseString(): string {
    const start = index;
    index += 1;
    for (;;) {
      if (index >= text.length) return fail('a string is not closed');
      const char = text[index] as string;
      if (char === '\\') {
        index += 2;
        continue;
      }
      if (char === '"') break;
      index += 1;
    }
    const slice = text.slice(start, index + 1);
    index += 1;
    try {
      const value = JSON.parse(slice) as unknown;
      if (typeof value !== 'string') return fail('a string is not well formed');
      return value;
    } catch {
      return fail('a string, or an escape inside one, is not well formed');
    }
  }

  const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[Ee][+-]?\d+)?/yu;

  function parseNumber(): number {
    NUMBER.lastIndex = index;
    const found = NUMBER.exec(text);
    const digits = found?.[0];
    if (digits === undefined || found?.index !== index) return fail('a number is not well formed');
    index += digits.length;
    return Number(digits);
  }

  function parseArray(): unknown[] {
    index += 1;
    const items: unknown[] = [];
    skipSpace();
    if (peek() === ']') {
      index += 1;
      return items;
    }
    for (;;) {
      items.push(parseValue());
      skipSpace();
      const char = peek();
      if (char === ',') {
        index += 1;
        continue;
      }
      if (char === ']') {
        index += 1;
        return items;
      }
      return fail('an array is missing a comma or its closing bracket');
    }
  }

  function parseObject(): Record<string, unknown> {
    index += 1;
    const entries: Array<[string, unknown]> = [];
    const seen = new Set<string>();
    skipSpace();
    if (peek() === '}') {
      index += 1;
      return {};
    }
    for (;;) {
      skipSpace();
      if (peek() !== '"') return fail('an object key must be a string in double quotes');
      const key = parseString();
      if (seen.has(key)) {
        throw invalid(`repeats the key '${key}' (${position()}); the value written first would be dropped`);
      }
      seen.add(key);
      skipSpace();
      if (peek() !== ':') return fail(`the object key '${key}' is not followed by a colon`);
      index += 1;
      entries.push([key, parseValue()]);
      skipSpace();
      const char = peek();
      if (char === ',') {
        index += 1;
        continue;
      }
      if (char === '}') {
        index += 1;
        return Object.fromEntries(entries);
      }
      return fail('an object is missing a comma or its closing brace');
    }
  }

  function parseValue(): unknown {
    skipSpace();
    switch (peek()) {
      case '{':
        return parseObject();
      case '[':
        return parseArray();
      case '"':
        return parseString();
      case 't':
        return word('true', true);
      case 'f':
        return word('false', false);
      case 'n':
        return word('null', null);
      default: {
        const char = peek();
        if (char === '-' || (char >= '0' && char <= '9')) return parseNumber();
        return fail('expected a value');
      }
    }
  }

  const value = parseValue();
  skipSpace();
  if (index < text.length) return fail('there is text after the end of the document');
  return value;
}

/** Code-unit ascending, deduplicated: the order a list of pins has no opinion about. */
function sortUnique<T>(items: readonly T[], key: (item: T) => string = (item) => String(item)): T[] {
  const unique = new Map<string, T>();
  for (const item of items) {
    if (!unique.has(key(item))) unique.set(key(item), item);
  }
  return [...unique.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, item]) => item);
}

/** A string a policy pins: not empty, and nothing in it that a reader cannot see. */
function pinnedText(label: string, value: unknown): string {
  if (typeof value !== 'string') throw invalid(`${label} must be a string, not ${spelled(value)}`);
  if (!PINNED_TEXT.test(value)) {
    throw invalid(
      `${label} must be a non-empty string holding no control, zero-width, bidi-override or line-separator character`,
    );
  }
  return value;
}

function hexBytes(label: string, value: unknown, bytes: number): string {
  const pattern = new RegExp(`^[0-9a-f]{${bytes * 2}}$`, 'u');
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw invalid(`${label} must be ${bytes * 2} hex characters in lowercase, which is ${bytes} bytes`);
  }
  return value;
}

function measurementHex(label: string, value: unknown, tee: TeeKind): string {
  const bytes = MEASUREMENT_BYTES[tee];
  const pattern = new RegExp(`^[0-9a-f]{${bytes * 2}}$`, 'u');
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw invalid(`${label} must be ${bytes * 2} hex characters in lowercase, the width tee '${tee}' measures`);
  }
  return value;
}

function base64Url32(label: string, value: unknown): string {
  if (typeof value !== 'string' || !BASE64URL_32_BYTES.test(value)) {
    throw invalid(`${label} must be the base64url of 32 bytes, which is 43 characters and no padding`);
  }
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(value);
  } catch (err) {
    throw invalid(`${label} is not base64url: ${err instanceof Error ? err.message : String(err)}`);
  }
  // The last character of a 43-character encoding holds two bits an encoder never sets, so several
  // spellings decode to one byte string. Two operators would then hold two documents naming the same
  // key with text that does not match, and a digest taken over the text would disagree with itself.
  const canonical = toBase64Url(bytes);
  if (canonical !== value) {
    throw invalid(`${label} is not the canonical base64url spelling of its own bytes, which are ${canonical}`);
  }
  return value;
}

function seconds(label: string, value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw invalid(`${label} must be a whole number of seconds of at least 1, not ${spelled(value)}`);
  }
  return value;
}

function pinList(field: string, value: unknown): string[] {
  const label = `'${field}'`;
  if (!Array.isArray(value)) throw invalid(`${label} must be an array of strings, not ${spelled(value)}`);
  if (value.length === 0) throw emptyPin(label);
  return sortUnique(value.map((item, at) => pinnedText(`${label}[${at}]`, item)));
}

function keyMap(value: unknown): Record<string, string> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalid(`'keys' must be an object keyed by kid, not ${spelled(value)}`);
  }
  const raw = value as Record<string, unknown>;
  const entries: Array<[string, string]> = [];
  for (const kid of Object.keys(raw).sort()) {
    if (!HEX_64.test(kid)) {
      throw invalid(`'keys' names a kid ${JSON.stringify(kid)}, which must be 64 lowercase hex characters`);
    }
    entries.push([kid, base64Url32(`'keys' entry for the kid '${kid}'`, raw[kid])]);
  }
  if (entries.length === 0) throw emptyPin("'keys'");
  return Object.fromEntries(entries);
}

function measurementMap(value: unknown): Record<string, readonly string[]> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalid(`'measurements' must be an object keyed by environment kind, not ${spelled(value)}`);
  }
  const raw = value as Record<string, unknown>;
  const entries: Array<[string, readonly string[]]> = [];
  for (const kind of Object.keys(raw).sort()) {
    if (!isTeeKind(kind)) {
      throw invalid(
        `'measurements' names the environment kind '${kind}', which this format does not know: ${Object.keys(MEASUREMENT_BYTES).join(', ')}`,
      );
    }
    const list = raw[kind];
    if (!Array.isArray(list)) {
      throw invalid(`'measurements.${kind}' must be an array of measurements, not ${spelled(list)}`);
    }
    if (list.length === 0) throw emptyPin(`'measurements.${kind}'`);
    entries.push([
      kind,
      sortUnique(list.map((item, at) => measurementHex(`'measurements.${kind}[${at}]'`, item, kind))),
    ]);
  }
  if (entries.length === 0) throw emptyPin("'measurements'");
  return Object.fromEntries(entries);
}

/**
 * A path below the directory holding the policy, spelled with forward slashes.
 *
 * Either separator is read as a separator, on every platform, so a document written on Windows and
 * audited on Linux names the same file and hashes to the same digest. The price is that a POSIX file
 * whose name genuinely contains a backslash cannot be pinned by this format, which is the trade a
 * document with a citable identity has to make.
 */
function anchorPath(label: string, value: unknown): string {
  if (typeof value !== 'string') throw invalid(`${label} must be a path string, not ${spelled(value)}`);
  const canonical = value.replaceAll('\\', '/');
  if (canonical.length === 0) throw invalid(`${label} must name a path, not an empty string`);
  if (!PINNED_TEXT.test(canonical)) {
    throw invalid(`${label} must not hold a control or otherwise invisible character`);
  }
  if (canonical.startsWith('/') || /^[A-Za-z]:/u.test(canonical) || isAbsolute(canonical)) {
    throw invalid(
      `${label} must be a path below the directory holding the policy file, not the absolute path ${JSON.stringify(canonical)}`,
    );
  }
  let depth = 0;
  let named = 0;
  for (const part of canonical.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      depth -= 1;
      if (depth < 0) {
        throw invalid(`${label} must not climb out of the directory holding the policy file`);
      }
      continue;
    }
    depth += 1;
    named += 1;
  }
  if (named === 0) {
    throw invalid(`${label} must name a file, and ${JSON.stringify(canonical)} names a directory`);
  }
  return canonical;
}

function anchorEntry(label: string, value: unknown): PolicyTrustAnchor {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalid(`${label} must be an object naming a path and its sha256, not ${spelled(value)}`);
  }
  const raw = value as Record<string, unknown>;
  for (const key of Object.keys(raw)) {
    if (key !== 'path' && key !== 'sha256') {
      throw invalid(`${label} has an unknown key '${key}'; one anchor entry defines path and sha256`);
    }
  }
  if (!('sha256' in raw)) {
    throw invalid(`${label} carries no sha256, so nothing would pin the bytes at its path`);
  }
  return {
    path: anchorPath(`${label}.path`, raw['path']),
    sha256: hexBytes(`${label}.sha256`, raw['sha256'], 32),
  };
}

function anchorFamily(label: string, value: unknown): PolicyAnchorFamily {
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value)) {
    throw invalid(`${label} must be a list of anchors, or null to accept the bundled root, not ${spelled(value)}`);
  }
  if (value.length === 0) return [];
  return sortUnique(
    value.map((entry, at) => anchorEntry(`${label}[${at}]`, entry)),
    (entry) => canonicalValue(entry),
  );
}

function readTrustAnchors(value: unknown): PolicyFileTrustAnchors {
  if (value === undefined || value === null) return { amdArks: null, intelSgxRoots: null, nvidiaRoots: null };
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw invalid(`'trustAnchors' must be an object, not ${spelled(value)}`);
  }
  const raw = value as Record<string, unknown>;
  for (const key of Object.keys(raw)) {
    if (!(ANCHOR_FAMILIES as readonly string[]).includes(key)) {
      throw invalid(
        `'trustAnchors' has an unknown key '${key}'; the families this format names are ${ANCHOR_FAMILIES.join(', ')}`,
      );
    }
  }
  return {
    amdArks: anchorFamily('trustAnchors.amdArks', raw['amdArks']),
    intelSgxRoots: anchorFamily('trustAnchors.intelSgxRoots', raw['intelSgxRoots']),
    nvidiaRoots: anchorFamily('trustAnchors.nvidiaRoots', raw['nvidiaRoots']),
  };
}

/**
 * Reads one policy document.
 *
 * The result is the document in its normalised spelling: sets sorted, every anchor family written
 * out, and both age windows present as a number or `null`. `policyFileDigest` is defined on this
 * form, so a digest is a fact about the policy and not about how a copy happened to be laid out.
 */
export function parsePolicyFile(text: string): PolicyFile {
  const document = scanJson(text);
  if (typeof document !== 'object' || document === null || Array.isArray(document)) {
    throw invalid(`must be a JSON object, not ${spelled(document)}`);
  }
  const raw = document as Record<string, unknown>;
  for (const key of Object.keys(raw)) {
    if (!(FIELDS as readonly string[]).includes(key)) {
      throw invalid(`has an unknown key '${key}' at the top level; this format defines ${FIELDS.join(', ')}`);
    }
  }
  if (raw['v'] !== POLICY_FORMAT_VERSION) {
    throw invalid(`'v' is ${spelled(raw['v'])}, but v must be ${POLICY_FORMAT_VERSION} to be read by this loader`);
  }
  const file: PolicyFile = {
    v: POLICY_FORMAT_VERSION,
    issuers: raw['issuers'] === undefined ? undefined : pinList('issuers', raw['issuers']),
    instances: raw['instances'] === undefined ? undefined : pinList('instances', raw['instances']),
    keys: raw['keys'] === undefined ? undefined : keyMap(raw['keys']),
    measurements: raw['measurements'] === undefined ? undefined : measurementMap(raw['measurements']),
    maxReceiptAgeSeconds:
      raw['maxReceiptAgeSeconds'] === undefined || raw['maxReceiptAgeSeconds'] === null
        ? null
        : seconds("'maxReceiptAgeSeconds'", raw['maxReceiptAgeSeconds']),
    maxEvidenceAgeSeconds:
      raw['maxEvidenceAgeSeconds'] === undefined || raw['maxEvidenceAgeSeconds'] === null
        ? null
        : seconds("'maxEvidenceAgeSeconds'", raw['maxEvidenceAgeSeconds']),
    trustAnchors: readTrustAnchors(raw['trustAnchors']),
  };
  requireSomePinning(file);
  return file;
}

/**
 * The rule a trust anchor has to hold: something must be pinned.
 *
 * A policy naming no issuer, instance, key or measurement accepts every receipt, which is the
 * opposite of why the object exists, and `verifyCompletionReceipt` reads an absent pin as no check.
 * An empty list is the same accident written differently. Both are refusals rather than defaults. A
 * vendor root pins nothing about a receipt, so it cannot satisfy this on its own.
 */
function requireSomePinning(file: PolicyFile): void {
  const pinned = PIN_FIELDS.filter((field) => file[field] !== undefined);
  if (pinned.length === 0) {
    throw new SdkError(
      'POLICY_NOTHING_PINNED',
      `policy file pins no issuers, instances, keys or measurements, so every receipt would be accepted: pin at least one of ${PIN_FIELDS.join(', ')}`,
    );
  }
}

/** The digest's serialization: every object's keys in code-unit order, arrays left in the order given. */
function canonicalValue(value: unknown): string {
  if (value === undefined || value === null) return 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalValue).join(',')}]`;
  if (typeof value !== 'object') return JSON.stringify(value);
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalValue(record[key])}`)
    .join(',')}}`;
}

/**
 * The loaded policy with every default written out and every set in one order.
 *
 * The shape is checked again on the way in, so a digest can never be published for an object that
 * carries a field this format does not define or lacks one it always normalises. Without that, a
 * caller that built a `PolicyFile` by hand could attach a digest to a policy the loader would have
 * refused.
 *
 * `trustAnchors` is the one field whose default is *not* filled in. Leaving a family out means
 * "accept the roots bundled with the verifier", and the bundled set is a property of whichever
 * `@ashaveri/attest-core` is installed rather than of this document, so writing those digests in
 * would tie a customer's signed identity to a library version. An unpinned family is written as
 * `null`, which says plainly that no root was pinned here.
 */
function canonicalOf(file: PolicyFile): Record<string, unknown> {
  const shape: unknown = file;
  if (typeof shape !== 'object' || shape === null || Array.isArray(shape)) {
    throw invalid(`must be a policy document, not ${spelled(file)}`);
  }
  const given = shape as Record<string, unknown>;
  for (const key of Object.keys(given)) {
    if (!(FIELDS as readonly string[]).includes(key)) {
      throw invalid(`has an unknown key '${key}' at the top level; this format defines ${FIELDS.join(', ')}`);
    }
  }
  if (given['v'] !== POLICY_FORMAT_VERSION) {
    throw invalid(`'v' is ${spelled(given['v'])}, but v must be ${POLICY_FORMAT_VERSION} to be read by this loader`);
  }
  for (const field of ['maxReceiptAgeSeconds', 'maxEvidenceAgeSeconds', 'trustAnchors'] as const) {
    if (given[field] === undefined) {
      throw invalid(`'${field}' is missing, so the document was never normalised by the loader`);
    }
  }
  const anchors = given['trustAnchors'] as Record<string, unknown>;
  for (const key of Object.keys(anchors)) {
    if (!(ANCHOR_FAMILIES as readonly string[]).includes(key)) {
      throw invalid(
        `'trustAnchors' has an unknown key '${key}'; the families this format names are ${ANCHOR_FAMILIES.join(', ')}`,
      );
    }
  }
  const written: Record<string, unknown> = {};
  for (const family of ANCHOR_FAMILIES) {
    const entries = anchors[family];
    written[family] = entries === undefined || entries === null ? null : sortUnique(entries as PolicyTrustAnchor[], canonicalValue);
  }
  const measurements = given['measurements'] as Record<string, readonly string[]> | undefined;
  return {
    issuers: given['issuers'] === undefined ? null : sortUnique(given['issuers'] as readonly string[]),
    instances: given['instances'] === undefined ? null : sortUnique(given['instances'] as readonly string[]),
    keys:
      given['keys'] === undefined
        ? null
        : Object.fromEntries(
            Object.entries(given['keys'] as Record<string, string>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
          ),
    measurements:
      measurements === undefined
        ? null
        : Object.fromEntries(
            Object.keys(measurements)
              .sort()
              .map((kind) => [kind, sortUnique(measurements[kind] ?? [])]),
          ),
    maxReceiptAgeSeconds: given['maxReceiptAgeSeconds'],
    maxEvidenceAgeSeconds: given['maxEvidenceAgeSeconds'],
    trustAnchors: written,
    v: POLICY_FORMAT_VERSION,
  };
}

/**
 * The digest of a policy: `sha256:` and 64 lowercase hex, over the canonical re-encoding of the
 * loaded policy, prefixed with this format's domain string.
 *
 * Two documents that mean one policy give one digest, and a matching digest is evidence that the
 * pins match, which is what lets an evidence pack cite a policy by it.
 */
export function policyFileDigest(file: PolicyFile): string {
  const encoded = new TextEncoder().encode(`${DIGEST_DOMAIN}${canonicalValue(canonicalOf(file))}`);
  return `${POLICY_DIGEST_PREFIX}${toHex(sha256(encoded))}`;
}

/**
 * The document form of a policy object, for a deployment that builds one in code and means to publish
 * it.
 *
 * An object's `trustAnchors` hold bytes with no name attached, and a file cannot carry bytes honestly,
 * so `anchorPaths` says where each family's bytes are to be found. The SHA-256 written into the
 * document is of the bytes given, not of whatever sits at the path later; whoever calls this writes
 * those files, and nothing here touches a disk. A family the object pins but `anchorPaths` names no
 * path for is a refusal, because an anchor dropped on the way to the file would be an anchor silently
 * unpinned.
 */
export function policyFileFromPolicy(
  policy: AshaveriPolicy,
  anchorPaths?: Partial<Record<AnchorFamily, readonly string[]>>,
): PolicyFile {
  const anchors: Record<string, unknown> = {};
  for (const family of ANCHOR_FAMILIES) {
    const bytes = policy.trustAnchors?.[family];
    if (bytes === undefined) {
      anchors[family] = null;
      continue;
    }
    if (bytes.length === 0) {
      anchors[family] = [];
      continue;
    }
    const paths = anchorPaths?.[family];
    if (paths === undefined || paths.length !== bytes.length) {
      throw invalid(
        `has no path to write for the ${bytes.length} ${family} root${bytes.length === 1 ? '' : 's'} the policy pins, so that anchor could not be named in the document`,
      );
    }
    anchors[family] = bytes.map((root, at) => ({ path: paths[at], sha256: toHex(sha256(root)) }));
  }
  const document: Record<string, unknown> = { v: POLICY_FORMAT_VERSION, trustAnchors: anchors };
  const lists: Array<[string, readonly string[] | undefined]> = [
    ['issuers', policy.issuers],
    ['instances', policy.instances],
  ];
  for (const [field, list] of lists) {
    if (list !== undefined) document[field] = [...list];
  }
  if (policy.keys !== undefined) document['keys'] = { ...policy.keys };
  if (policy.measurements !== undefined) {
    document['measurements'] = Object.fromEntries(
      Object.entries(policy.measurements).map(([kind, list]) => [kind, [...list]]),
    );
  }
  document['maxReceiptAgeSeconds'] = policy.maxReceiptAgeSeconds ?? null;
  document['maxEvidenceAgeSeconds'] = policy.maxEvidenceAgeSeconds ?? null;
  return parsePolicyFile(JSON.stringify(document));
}

/** Two spaces, keys in code-unit order, a trailing newline: the form worth putting in a repository. */
export function policyFileToJson(file: PolicyFile): string {
  const canonical = canonicalOf(file);
  const write: Record<string, unknown> = {};
  for (const field of PIN_FIELDS) {
    const value = canonical[field];
    if (value !== null) write[field] = value;
  }
  write['maxReceiptAgeSeconds'] = canonical['maxReceiptAgeSeconds'];
  write['maxEvidenceAgeSeconds'] = canonical['maxEvidenceAgeSeconds'];
  write['trustAnchors'] = canonical['trustAnchors'];
  write['v'] = canonical['v'];
  return `${JSON.stringify(rekeySorted(write), null, 2)}\n`;
}

/** Sorts every object's keys, leaving arrays as the ordered lists the format says they are. */
function rekeySorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(rekeySorted);
  if (value === null || typeof value !== 'object') return value;
  const record = value as Record<string, unknown>;
  return Object.fromEntries(
    Object.keys(record)
      .sort()
      .map((key) => [key, rekeySorted(record[key])]),
  );
}

async function readAnchorBytes(path: string, label: string): Promise<Uint8Array> {
  try {
    return new Uint8Array(await readFile(path));
  } catch (err) {
    throw new SdkError(
      'POLICY_ANCHOR_UNREADABLE',
      `policy file cannot read the trust anchor ${label}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Resolves an anchor path below the directory holding the policy, and refuses one that escapes it
 * once the platform has had its say about separators.
 *
 * `anchorPath` already rejects a path that climbs out lexically; this is the same rule against the
 * real filesystem. Together they mean the path a digest names is the path the bytes came from.
 */
function resolveAnchor(baseDir: string, path: string, label: string): string {
  const base = resolve(baseDir);
  const target = resolve(base, path);
  const under = relative(base, target);
  if (under === '' || under === '..' || under.startsWith(`..${sep}`) || isAbsolute(under)) {
    throw invalid(`${label} resolves outside the directory holding the policy file`);
  }
  return target;
}

async function loadAnchors(
  file: PolicyFile,
  baseDir: string,
): Promise<{ readonly anchors: LoadedPolicyAnchor[]; readonly trustAnchors?: EvidenceTrustAnchors }> {
  const anchors: LoadedPolicyAnchor[] = [];
  const families: Partial<Record<AnchorFamily, Uint8Array[]>> = {};
  for (const family of ANCHOR_FAMILIES) {
    const entries = file.trustAnchors[family];
    if (entries === null) continue;
    const bytes: Uint8Array[] = [];
    for (const [at, entry] of entries.entries()) {
      const label = `trustAnchors.${family}[${at}]`;
      const target = resolveAnchor(baseDir, entry.path, `${label}.path`);
      const read = await readAnchorBytes(target, `${entry.path} (named at ${label})`);
      const digest = toHex(sha256(read));
      if (digest !== entry.sha256) {
        throw new SdkError(
          'POLICY_ANCHOR_DIGEST_MISMATCH',
          `policy file pins ${entry.path} at ${label} by sha256 ${entry.sha256}, but the bytes there hash to ${digest}`,
        );
      }
      anchors.push({ family, path: entry.path, sha256: entry.sha256 });
      bytes.push(read);
    }
    families[family] = bytes;
  }
  if (Object.keys(families).length === 0) return { anchors };
  return { anchors, trustAnchors: families };
}

function toPolicy(file: PolicyFile, anchors: EvidenceTrustAnchors | undefined): AshaveriPolicy {
  const policy: AshaveriPolicy = {
    issuers: file.issuers,
    instances: file.instances,
    keys: file.keys,
    measurements: file.measurements,
    maxReceiptAgeSeconds: file.maxReceiptAgeSeconds ?? undefined,
    maxEvidenceAgeSeconds: file.maxEvidenceAgeSeconds ?? undefined,
  };
  return anchors === undefined ? policy : { ...policy, trustAnchors: anchors };
}

/**
 * Reads, validates and resolves one policy document, from its text and the directory its anchor paths
 * are written against.
 */
export async function loadPolicyFromText(text: string, baseDir: string): Promise<LoadedPolicy> {
  const file = parsePolicyFile(text);
  const { anchors, trustAnchors } = await loadAnchors(file, baseDir);
  return { file, policy: toPolicy(file, trustAnchors), digest: policyFileDigest(file), anchors };
}

/** Reads a policy file from disk. Anchor paths resolve against the directory holding it. */
export async function loadPolicyFile(path: string): Promise<LoadedPolicy> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (err) {
    throw new SdkError(
      'POLICY_FILE_UNREADABLE',
      `cannot read the policy file '${path}': ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return loadPolicyFromText(text, dirname(resolve(path)));
}
