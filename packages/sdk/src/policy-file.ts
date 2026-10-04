import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { sha256 } from '@noble/hashes/sha2.js';
import { MEASUREMENT_BYTES, isTeeKind, type TeeKind } from '@ashaveri/receipt';
import { fromBase64Url, toBase64Url, toHex } from './b64.js';
import { SdkError } from './errors.js';
import { ATTESTED_TEXT_MEMBERS, attestedTextShape, MAX_ANCHOR_SLOTS_DEMANDABLE } from './policy.js';
import type { AshaveriPolicy, AttestedTextMember } from './policy.js';
import type { EvidenceTrustAnchors } from './evidence.js';
import { DEFAULT_MAX_EVIDENCE_AGE_SECONDS, DEFAULT_MAX_RECEIPT_AGE_SECONDS } from './policy.js';

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
  'maxTimeUncertaintySeconds',
  'minAnchorSlotsHeld',
  'minAnchorSlotsWeighed',
  'attestedTextShapes',
  'trustAnchors',
] as const;

/** The fields that pin a receipt to something. A policy has to name at least one of them. */
const PIN_FIELDS = ['issuers', 'instances', 'keys', 'measurements'] as const;

/**
 * `AshaveriPolicy.manifestKeys`, the keys a client designates to authenticate its deployment manifest,
 * is not a field of this document, and a file that names one is refused as an unknown key rather than
 * read and dropped. That is a decision about an identity and not a piece of unfinished work.
 *
 * Every field of a policy is inside its digest, and the digest is how a capture record and an evidence
 * pack cite the policy a verdict was reached under. Writing the new field out normalised, which is what
 * this format does with every optional field, would move the digest of every policy already written,
 * including those nobody will ever add the field to, and would quietly invalidate the citations made
 * against them. Leaving it out of the canonical form while carrying it in the document would put a pin
 * an operator wrote outside the identity of the file holding it, which is the failure this format exists
 * to prevent.
 *
 * `policyFileFromPolicy` refuses the first of those two trades rather than making it, so a policy that
 * designates a manifest signer stays a policy built in code until moving every digest is decided in the
 * open.
 */

/**
 * Two fields of this document have a conditional normalised spelling: `maxTimeUncertaintySeconds`
 * and `minAnchorSlotsHeld` are written into the canonical form only where the document stated a
 * number, and the trade is the opposite of the one above, taken deliberately and in the open. A
 * manifest signing key is a pin: reading it from the file while leaving it out of the canonical form
 * would set a trust decision outside the identity of the document that states it. A demand about how
 * far a stamp's source may stand from real time, or about how many of an anchor's slots were taken
 * in, is not a pin and pins nothing on its own, so the only case a canonical omission would lose is
 * the case where nothing was demanded, which is every policy already written and already cited by a
 * digest. So a number an operator states is always inside the canonical form and always inside the
 * digest, and an absent demand is omitted from the canonical form rather than written as `null`. The
 * rule as implemented is at `canonicalOf`.
 */

/**
 * `minAnchorSlotsHeld` is the second of the two conditional fields, and its trade is the note
 * above's. `test/anchor-slot-demand.test.ts` holds that sentence to numbers: the digests of
 * documents that never named the field, and the verdicts those documents reach.
 */

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
 * an explicit `null`, which is how a document says it considered them and took the default. The time
 * bound and the anchor demand both accept `null` on the same reading, and they are the two fields the
 * canonical form normalises by omission rather than writes: see the note above this interface on why a
 * demand is normalised by omission and the two windows are not.
 */
export interface PolicyFile {
  readonly v: number;
  readonly issuers?: readonly string[];
  readonly instances?: readonly string[];
  readonly keys?: Readonly<Record<string, string>>;
  readonly measurements?: Readonly<Record<string, readonly string[]>>;
  readonly maxReceiptAgeSeconds: number | null;
  readonly maxEvidenceAgeSeconds: number | null;
  /**
   * How far the source a stamp was read from may stand from the instant it names, or `null` when the
   * document demands nothing about it. An unsigned number, so `0` is a demand and says what it demands.
   *
   * How many of a receipt's anchor slots this verifier requires to state that their material was taken
   * in and is held, or `null` where the document demands nothing about an anchor. A whole number of
   * slots from 1 to `MAX_ANCHOR_SLOTS_DEMANDABLE`, so `1` is a demand and says what it demands.
   *
   * `null` and an absent field are one policy here, as they are for the two windows above. What differs
   * is the spelling that policy gets in the canonical form, which `canonicalOf` states and explains.
   */
  readonly maxTimeUncertaintySeconds: number | null;
  readonly minAnchorSlotsHeld: number | null;
  /**
   * How many of a receipt's anchor slots this verifier requires its reader to have reached, and to have found
   * standing as their own signed statement at the instant the receipt states, or `null` where the document demands
   * nothing about it. The same whole number of slots, from 1 to `MAX_ANCHOR_SLOTS_DEMANDABLE`, on the same grounds.
   *
   * What the field above reads out of the artifact, this one reads out of the material the artifact digests, so the
   * two may be stated together or apart. A document naming only this one demands weighed material of whichever slots
   * state they were taken in and asks nothing beside that count.
   */
  readonly minAnchorSlotsWeighed: number | null;
  /**
   * The shape each text member a deployment authors has to match, keyed by the payload's own member names, or `null`
   * where the document names none. Each value is a regular expression source, and this loader compiles it before it
   * keeps the policy: a source that compiles to nothing and one the empty text matches are both refused, because each
   * spells a demand that asks nothing of the member it is named for.
   *
   * A key this format names no position for is refused as an unknown one rather than read and dropped, which is what
   * keeps a demand an operator wrote inside the identity of the file stating it.
   */
  readonly attestedTextShapes: Readonly<Partial<Record<AttestedTextMember, string>>> | null;
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

/**
 * A whole number of seconds at or above `least`. `Number.isSafeInteger` is the check that refuses a
 * value past the point an integer stops being exact: a bound a reader cannot state exactly is not the
 * bound the document names, and the digits in the file and the number the loader keeps would be two
 * different demands.
 *
 * The two windows take a floor of 1, where a window of no seconds is a refusal rather than a window.
 * The time bound takes a floor of 0, because demanding that a stamp's source be exact is a sentence an
 * operator can mean and the format has to be able to carry it.
 */
function seconds(label: string, value: unknown, least: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < least) {
    throw invalid(`${label} must be a whole number of seconds of at least ${least}, not ${spelled(value)}`);
  }
  return value;
}

/**
 * A count of an anchor's slots at `minAnchorSlotsHeld` or `minAnchorSlotsWeighed`, whole, at least one, and no more
 * than the slots an anchor has. The `says` argument is what the count demands of them, taken in or weighed, because
 * the two counts bound the same two slots and answer to different sentences.
 *
 * This is a deliberate neighbour of `seconds` and not that function with a different name attached: the
 * quantity is a count of members of a signed map rather than a duration, so a non-finite value is refused
 * here for the reason the two windows refuse it and an out-of-range value is refused for one they have no
 * equivalent of. `Number.isSafeInteger` is what catches `1e400` on the way in, which a JSON document of
 * this shape can spell and no reader can state exactly: digits in the file and the number the loader keeps
 * would be two different demands.
 *
 * Both bounds are refusals rather than clamps, and each message names the two roads open to whoever wrote
 * the number. Below one: a demand of no slots is met by every artifact ever issued, so it is a silence
 * written as a decision, and the road out is to leave the field out, which is what this format's spelling
 * of demanding nothing is. Above the slot count: no document can ever meet it, so the road out is to lower
 * it to the count the anchor holds or to leave it out, and never to leave a policy standing that has
 * already refused everything it will ever be shown.
 */
function anchorSlots(label: string, value: unknown, says: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw invalid(
      `${label} must be a whole number of slots from 1 to ${MAX_ANCHOR_SLOTS_DEMANDABLE}, not ${spelled(value)}: a demand stated as a fraction or as no number at all is weighed against nothing, so either name that many of the anchor's slots or leave the field out, which is what this format's spelling of demanding nothing about an anchor is`,
    );
  }
  if (value < 1 || value > MAX_ANCHOR_SLOTS_DEMANDABLE) {
    throw invalid(
      `${label} is ${String(value)}, which no document can answer: an anchor states ${MAX_ANCHOR_SLOTS_DEMANDABLE} slots, so a demand is a whole number from 1 to ${MAX_ANCHOR_SLOTS_DEMANDABLE} naming ${says}, and either name that many or leave the field out, which is what this format's spelling of demanding nothing about an anchor is`,
    );
  }
  return value;
}

/**
 * The shapes a document demands of the text members a deployment authors, keyed by the payload's own member names.
 *
 * Two refusals and both are about a demand that cannot be met rather than a demand that is hard to meet. A key
 * outside `ATTESTED_TEXT_MEMBERS` names no text this reader can run a rule over, so it is refused as the unknown keys
 * this format refuses everywhere else: a demand dropped on the way to a verdict is a demand an auditor believes they
 * made. A value that is not a regular expression, or one the empty text matches, is refused by `attestedTextShape`,
 * the same function the check itself compiles with, so the shape that reaches a verdict is the shape that was written
 * into the digest.
 *
 * Keys are kept in code-unit order, because this map rides in the canonical form and a document's formatting is not
 * allowed to choose its own digest.
 */
function textShapes(value: unknown): Partial<Record<AttestedTextMember, string>> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalid(`'attestedTextShapes' must be an object keyed by payload member, not ${spelled(value)}`);
  }
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).length === 0) {
    throw new SdkError(
      'POLICY_EMPTY_PIN',
      'policy file \'attestedTextShapes\' is an empty map, which demands nothing of any member: name a shape for at least one text member, or leave the field out, which is what this format\'s spelling of demanding nothing about a deployment\'s text is',
    );
  }
  const shapes: Partial<Record<AttestedTextMember, string>> = {};
  for (const member of Object.keys(raw).sort()) {
    const named = ATTESTED_TEXT_MEMBERS.find((one) => one === member);
    if (named === undefined) {
      throw invalid(
        `'attestedTextShapes' names '${member}', which is no text member a receipt of this format carries: the positions a shape can be demanded of are ${ATTESTED_TEXT_MEMBERS.join(', ')}, and a demand this reader cannot run is not one it keeps`,
      );
    }
    const stated = pinnedText(`'attestedTextShapes.${member}'`, raw[member]);
    attestedTextShape(stated);
    shapes[named] = stated;
  }
  return shapes;
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
 * out, both age windows, the time bound and the anchor demand each present as a number or `null`.
 * `policyFileDigest` is defined on this form, so a digest is a fact about the policy and not about how a
 * copy happened to be laid out.
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
        : seconds("'maxReceiptAgeSeconds'", raw['maxReceiptAgeSeconds'], 1),
    maxEvidenceAgeSeconds:
      raw['maxEvidenceAgeSeconds'] === undefined || raw['maxEvidenceAgeSeconds'] === null
        ? null
        : seconds("'maxEvidenceAgeSeconds'", raw['maxEvidenceAgeSeconds'], 1),
    maxTimeUncertaintySeconds:
      raw['maxTimeUncertaintySeconds'] === undefined || raw['maxTimeUncertaintySeconds'] === null
        ? null
        : seconds("'maxTimeUncertaintySeconds'", raw['maxTimeUncertaintySeconds'], 0),
    minAnchorSlotsHeld:
      raw['minAnchorSlotsHeld'] === undefined || raw['minAnchorSlotsHeld'] === null
        ? null
        : anchorSlots("'minAnchorSlotsHeld'", raw['minAnchorSlotsHeld'], 'how many of them must have been taken in'),
    minAnchorSlotsWeighed:
      raw['minAnchorSlotsWeighed'] === undefined || raw['minAnchorSlotsWeighed'] === null
        ? null
        : anchorSlots("'minAnchorSlotsWeighed'", raw['minAnchorSlotsWeighed'], 'how many of them a reader must reach and find standing'),
    attestedTextShapes:
      raw['attestedTextShapes'] === undefined || raw['attestedTextShapes'] === null
        ? null
        : textShapes(raw['attestedTextShapes']),
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
 * `trustAnchors` is the one field whose default is *not* filled in with the thing it stands for. Leaving a
 * family out means
 * "accept the roots bundled with the verifier", and the bundled set is a property of whichever
 * `@ashaveri/attest-core` is installed rather than of this document, so writing those digests in
 * would tie a customer's signed identity to a library version. An unpinned family is written as
 * `null`, which says plainly that no root was pinned here. The two fields the form leaves out of the
 * document altogether when nothing was stated are the time bound and the anchor demand below: neither
 * has a default to substitute, so each writes nothing rather than a `null` that would move every
 * digest cited before it.
 *
 * `maxTimeUncertaintySeconds` is written only when the document states a demand. A number an operator
 * named is a decision this policy carries, so it is inside the canonical form and inside the digest,
 * and whoever holds the document can see from it alone, without asking the deployment, whether a bound
 * on a stamp's source was asked for. A demand nobody stated is written as nothing at all rather than as
 * `null`, so the field's existence moves no digest that never named it, and `test/policy-replay.test.ts`
 * pins that fact as numbers rather than as this sentence.
 *
 * `minAnchorSlotsHeld` is written only when stated, under the same rule; the trade is argued at the
 * note above `PolicyFile`.
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
  // The fields the loader always spells, so a document missing one was never read by it. The time bound
  // is absent from this list on purpose and not by oversight: `null` and no key at all are one demand
  // there, as the note above `PolicyFile` argues, and a guard that asked a hand-built document to state
  // the key would be one step from a canonical form that always carries it, which moves every digest
  // anyone has cited.
  for (const field of ['maxReceiptAgeSeconds', 'maxEvidenceAgeSeconds', 'trustAnchors'] as const) {
    if (given[field] === undefined) {
      throw invalid(`'${field}' is missing, so the document was never normalised by the loader`);
    }
  }
  // Same deliberate omission for the anchor demand, per the note above `PolicyFile`.
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
  const canonical: Record<string, unknown> = {
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
  const demanded = given['maxTimeUncertaintySeconds'];
  if (demanded !== undefined && demanded !== null) canonical['maxTimeUncertaintySeconds'] = demanded;
  const demandedSlots = given['minAnchorSlotsHeld'];
  if (demandedSlots !== undefined && demandedSlots !== null) canonical['minAnchorSlotsHeld'] = demandedSlots;
  // Both of the fields below take the same conditional spelling as the count above, on the same grounds: what an
  // operator states is inside the identity, and what nobody stated leaves the canonical form exactly as it was before
  // the field existed, so no digest anyone has cited moves because a demand became possible to write.
  const weighedSlots = given['minAnchorSlotsWeighed'];
  if (weighedSlots !== undefined && weighedSlots !== null) canonical['minAnchorSlotsWeighed'] = weighedSlots;
  const shapes = given['attestedTextShapes'] as Record<string, string> | null | undefined;
  if (shapes !== undefined && shapes !== null) {
    canonical['attestedTextShapes'] = Object.fromEntries(
      Object.keys(shapes).sort().map((member) => [member, shapes[member] as string]),
    );
  }
  return canonical;
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
  if (policy.manifestKeys !== undefined && Object.keys(policy.manifestKeys).length > 0) {
    const count = Object.keys(policy.manifestKeys).length;
    throw invalid(
      `carries no field for the ${count} manifest signing key${count === 1 ? '' : 's'} this policy designates, and writing them out would move the digest of every policy file already cited: a policy that pins who signs its deployment manifest is built in code until adding the field is decided against those citations`,
    );
  }
  if (policy.keys !== undefined) document['keys'] = { ...policy.keys };
  if (policy.measurements !== undefined) {
    document['measurements'] = Object.fromEntries(
      Object.entries(policy.measurements).map(([kind, list]) => [kind, [...list]]),
    );
  }
  // A window this text form cannot spell is refused here, while each number is still in hand, on the
  // same rule the stamp-source demand below is held to. A non-finite window survives no further than
  // `JSON.stringify`, which writes it as `null`, and `null` in one of these two keys is this format's
  // spelling of a policy that names no window of its own: a reader of the published document would then
  // run the shipped default the operator meant to switch off. The off switch lives where it works, on
  // the policy object a calling process hands to a verifier. The message says both of that operator's
  // two ways out, because dropping the field is not one of them: it lands on the same default this
  // refusal exists to keep out of a published document.
  const windows: Array<[string, number | undefined, number, number]> = [
    ['maxReceiptAgeSeconds', policy.maxReceiptAgeSeconds, DEFAULT_MAX_RECEIPT_AGE_SECONDS, 1],
    ['maxEvidenceAgeSeconds', policy.maxEvidenceAgeSeconds, DEFAULT_MAX_EVIDENCE_AGE_SECONDS, 1],
  ];
  for (const [field, named, shipped, floor] of windows) {
    if (named !== undefined && !Number.isFinite(named)) {
      throw invalid(
        `'${field}' is ${String(named)}, which no policy document can carry as a window: the written form of it is null, and null is this format's spelling of a policy that names no window of its own, so publishing this policy would pin the shipped ${shipped}-second default instead. Name a whole number of seconds at or above ${floor} for '${field}', or keep the open window on the policy object this process hands to a verifier: leaving '${field}' out of the document is that same default, not this refusal switched off`,
      );
    }
  }
  document['maxReceiptAgeSeconds'] = policy.maxReceiptAgeSeconds ?? null;
  document['maxEvidenceAgeSeconds'] = policy.maxEvidenceAgeSeconds ?? null;
  // Written only when the policy states a demand, which is the reading the canonical form takes too: a
  // policy that demands nothing about a stamp's source is the policy that existed before this field
  // did, and its digest says so by carrying no key for it.
  if (policy.maxTimeUncertaintySeconds !== undefined) {
    // Refused here, while the number is still in hand. A non-finite demand survives no further than the
    // text form of this document, which writes it as `null`, and `null` is this format's spelling of a
    // policy that asks nothing of a stamp's source, so the demand would reach an auditor as its absence.
    if (!Number.isFinite(policy.maxTimeUncertaintySeconds)) {
      throw invalid(
        `'maxTimeUncertaintySeconds' is ${String(policy.maxTimeUncertaintySeconds)}, which no policy document can carry as a demand: the written form of it is null, and null is this format's spelling of a policy that asks nothing of a stamp's source`,
      );
    }
    document['maxTimeUncertaintySeconds'] = policy.maxTimeUncertaintySeconds;
  }

  // The anchor's leg takes the same reading: a
  // policy that demands nothing about an anchor is the policy that existed before this field did, and its
  // digest says so by carrying no key for it.
  if (policy.minAnchorSlotsHeld !== undefined) {
    // Refused here, while the number is still in hand. A non-finite demand survives no further than the
    // text form of this document, which writes it as `null`, and `null` is this format's spelling of a
    // policy that asks nothing of an anchor, so a demand an operator wrote would reach an auditor as its
    // own absence. The two roads are the two the loader's own refusal names: state a demand a document can
    // meet, or name no demand at all.
    if (!Number.isFinite(policy.minAnchorSlotsHeld)) {
      throw invalid(
        `'minAnchorSlotsHeld' is ${String(policy.minAnchorSlotsHeld)}, which no policy document can carry as a demand: the written form of it is null, and null is this format's spelling of a policy that asks nothing of an anchor, so either state a whole number of the anchor's ${String(MAX_ANCHOR_SLOTS_DEMANDABLE)} slots or name no demand at all`,
      );
    }
    document['minAnchorSlotsHeld'] = policy.minAnchorSlotsHeld;
  }

  // The weighed count takes the same reading as the count above, for the same reason and with the same two
  // roads open: a demand a document cannot spell reaches an auditor as the absence of one.
  if (policy.minAnchorSlotsWeighed !== undefined) {
    if (!Number.isFinite(policy.minAnchorSlotsWeighed)) {
      throw invalid(
        `'minAnchorSlotsWeighed' is ${String(policy.minAnchorSlotsWeighed)}, which no policy document can carry as a demand: the written form of it is null, and null is this format's spelling of a policy that asks nothing of an anchor's material, so either state a whole number of the anchor's ${String(MAX_ANCHOR_SLOTS_DEMANDABLE)} slots or name no demand at all`,
      );
    }
    document['minAnchorSlotsWeighed'] = policy.minAnchorSlotsWeighed;
  }

  // The shapes ride out only where the policy names at least one, which is the reading the canonical form
  // takes of both anchor counts: a policy that demanded nothing about a deployment's text is the policy that
  // existed before this field did, and its digest says so by carrying no key for it. Each source is compiled
  // here, on the way out as on the way in, because a policy built in code reaches a verifier without ever
  // passing through the loader, and a shape that compiles to nothing would arrive as a demand met by nothing.
  const shapes = policy.attestedTextShapes;
  if (shapes !== undefined && Object.keys(shapes).length > 0) {
    document['attestedTextShapes'] = Object.fromEntries(
      Object.keys(shapes).sort().map((member) => {
        const source = shapes[member as AttestedTextMember] as string;
        attestedTextShape(source);
        return [member, source];
      }),
    );
  }
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
  // A demand that was never made is not written into the file, exactly as `canonicalOf` leaves it out
  // of the identity, so the text worth putting in a repository reads the same as the digest does.
  if (canonical['maxTimeUncertaintySeconds'] !== undefined) {
    write['maxTimeUncertaintySeconds'] = canonical['maxTimeUncertaintySeconds'];
  }

  // Same omission for the anchor demand.
  if (canonical['minAnchorSlotsHeld'] !== undefined) {
    write['minAnchorSlotsHeld'] = canonical['minAnchorSlotsHeld'];
  }
  if (canonical['minAnchorSlotsWeighed'] !== undefined) {
    write['minAnchorSlotsWeighed'] = canonical['minAnchorSlotsWeighed'];
  }
  if (canonical['attestedTextShapes'] !== undefined) {
    write['attestedTextShapes'] = canonical['attestedTextShapes'];
  }
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
    maxTimeUncertaintySeconds: file.maxTimeUncertaintySeconds ?? undefined,
    minAnchorSlotsHeld: file.minAnchorSlotsHeld ?? undefined,
    minAnchorSlotsWeighed: file.minAnchorSlotsWeighed ?? undefined,
    attestedTextShapes: file.attestedTextShapes ?? undefined,
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
