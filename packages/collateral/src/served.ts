import { p256 } from '@noble/curves/nist.js';
import { derEcdsaSignature, type ParsedCertificate } from '@ashaveri/attest-core';
import { utf8 } from './bytes.js';
import { collateralRefusal, quoteOrDigest, type CollateralRefusal } from './errors.js';
import type { OriginDeclaration } from './intel-origin.js';
import {
  decodeText,
  parseCertificates,
  parsePinned,
  reachAnchor,
  readStatement,
  verifiesUnderLeaf,
  type Reading,
  type ReadOutcome,
} from './read.js';

/**
 * Reads the answer the origin actually serves: the body and the issuer chain that arrived beside it.
 *
 * The envelope here is the one `declaration.signature.served` states, as cited beside each declaration in
 * `intel-origin.ts`: a JSON wrapper holding the document under
 * the member `window.documentMember` names, a `signature` member of 128 lowercase hex characters, and the
 * certificates in a response header rather than inside the body. Which bytes those 64 stand for is the measured
 * part that decides this file's shape: the signature is taken over the **span of the document member inside the
 * body text**, so this reads the member's text out of the answer instead of re-making it from the parsed object,
 * because the same document re-serialized with its keys sorted is a different sequence of bytes and the
 * signature does not hold over it. Nothing here has verified what any vendor's document states; the rule read
 * off the served answers is about the shape an answer arrives in and which bytes its signature covers.
 *
 * The order is the one `read.ts` keeps: believe, then read. The span is located, the chain is decoded and
 * walked to a root the caller named, and only then is the signature checked over the span and the document's
 * own window, identity and status read. The chain walk, the pinned set and the document read are that file's,
 * so both envelopes settle the same questions the same way and differ only in where the certificates come from
 * and what the signature is taken over.
 */
export function readServedCollateral(body: Uint8Array, chain: Uint8Array | null, reading: Reading): ReadOutcome {
  const { declaration } = reading;
  const served = declaration.signature.served;
  if (served === null) {
    return refused(declaration, 'the declaration names no served envelope, so no pair is weighed here');
  }
  const member = declaration.window.documentMember;
  if (member === null) {
    return refused(declaration, 'the served envelope signs the document member its declaration names, and this one names none');
  }
  const text = decodeText(body, declaration);
  if (typeof text !== 'string') {
    return text;
  }
  const payload = topLevelObject(text, declaration);
  if ('refusal' in payload) {
    return payload;
  }
  const span = memberSpan(text, member, declaration);
  if ('refusal' in span) {
    return span;
  }
  const signature = memberString(text, served.signatureMember, declaration);
  if ('refusal' in signature) {
    return signature;
  }
  if (chain === null) {
    return unweighed(reading, payload.read);
  }
  const presented = chainCertificates(chain, declaration);
  if ('refusal' in presented) {
    return presented;
  }
  const pinned = parsePinned(reading.query.roots, declaration);
  if ('refusal' in pinned) {
    return pinned;
  }
  const anchor = reachAnchor(presented.certificates, pinned, reading, declaration);
  if ('refusal' in anchor) {
    return anchor;
  }
  const pair = rawPair(signature.value, served.signatureMember, declaration);
  if ('refusal' in pair) {
    return pair;
  }
  const der = derForm(pair.read, declaration);
  if ('refusal' in der) {
    return der;
  }
  if (!verifiesUnderLeaf(presented.certificates[0] as ParsedCertificate, utf8(span.text), der.read)) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.signature,
        `the signature does not hold over the ${member} span the body arrived with`,
      ),
    };
  }
  const stated = readStatement(payload.read, reading);
  if ('refusal' in stated) {
    return stated;
  }
  return { read: { ...stated, anchorDigest: anchor.digest, blobs: [body, ...presented.der] } };
}

/** The certificates the header carried, in the order it carried them, and the DER of each. */
interface Presented {
  readonly certificates: ParsedCertificate[];
  readonly der: Uint8Array[];
}

/**
 * The chain half of the pair, read the way the capture left it.
 *
 * The fetch keeps the header's bytes exactly as they arrived, and this is the seam that decides to decode them:
 * URL-decode, then let the platform's own X.509 reader split the blocks, which accepts PEM and DER alike. Both
 * steps throw on input a vendor would never send, and both are answers here rather than exceptions, because a
 * chain that is not a chain is a refusal about the answer and not a fault in the caller.
 */
function chainCertificates(chain: Uint8Array, declaration: OriginDeclaration): Presented | { readonly refusal: CollateralRefusal } {
  const header = quoteOrDigest(declaration.chainHeader ?? 'a header this declaration does not name');
  const encoded = decodeText(chain, declaration);
  if (typeof encoded !== 'string') {
    return refused(declaration, `the chain in ${header} is not UTF-8 text`);
  }
  let pem: string;
  try {
    pem = decodeURIComponent(encoded);
  } catch {
    return refused(declaration, `the chain in ${header} is not URL-encoded text`);
  }
  const certificates = parseCertificates(utf8(pem));
  if (certificates === null || certificates.length === 0) {
    return refused(declaration, `the chain in ${header} holds no certificate that parses`);
  }
  return { certificates, der: certificates.map((one) => one.raw) };
}

/**
 * The `signature` member read as the raw pair it states: two 32-byte integers, big-endian, no DER wrapper.
 *
 * The width and the alphabet are the rule, and a pair that fails them is refused rather than handed to the
 * curve: a DER signature is a perfectly good signature and is not what this envelope states, and one reader
 * that took either would accept a shape the origin never answers with.
 */
function rawPair(text: string, member: string, declaration: OriginDeclaration): { readonly read: Uint8Array } | { readonly refusal: CollateralRefusal } {
  if (!/^[0-9a-f]{128}$/u.test(text)) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.envelope,
        `the ${member} member is not the 128 lowercase hex characters this envelope states (${String(text.length)} characters)`,
      ),
    };
  }
  const bytes = new Uint8Array(64);
  for (let at = 0; at < 64; at += 1) {
    bytes[at] = Number.parseInt(text.slice(at * 2, at * 2 + 2), 16);
  }
  return { read: bytes };
}

/**
 * The raw pair as DER, which is what this curve verifies.
 *
 * `derEcdsaSignature` is the converter `@ashaveri/attest-core` already uses for a quote's raw signature, and it
 * range-checks both integers against the curve order before it encodes them, so a pair of numbers that is not a
 * signature at all answers with a refusal here rather than an exception from inside the arithmetic. Writing a
 * second converter is how that check goes missing.
 */
function derForm(pair: Uint8Array, declaration: OriginDeclaration): { readonly read: Uint8Array } | { readonly refusal: CollateralRefusal } {
  const half = pair.length / 2;
  try {
    return { read: derEcdsaSignature(bigEndian(pair.subarray(0, half)), bigEndian(pair.subarray(half)), p256.Point.CURVE().n) };
  } catch {
    return {
      refusal: collateralRefusal(
        declaration.refusals.signature,
        'the raw pair the signature member holds is outside the range this curve signs in',
      ),
    };
  }
}

function bigEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const one of bytes) {
    value = (value << 8n) | BigInt(one);
  }
  return value;
}

/**
 * The refusal for a body that arrived with no chain beside it.
 *
 * Absence at the fetch is not absence of the document, so this says which header carried nothing and quotes what
 * the body states under it. The words are the body's own and they are quoted as outside text, because the walk
 * that would have established them had no certificates to walk: no status and no window out of this sentence
 * reaches a verdict, a classification or a claim.
 */
function unweighed(reading: Reading, payload: Record<string, unknown>): { readonly refusal: CollateralRefusal } {
  const { declaration } = reading;
  const header = quoteOrDigest(declaration.chainHeader ?? 'a header this declaration does not name');
  const stated = readStatement(payload, reading);
  const words = 'refusal' in stated
    ? ', and it states no document this path reads'
    : `, and it states ${quoteOrDigest(stated.vendorStatus)} for ${quoteOrDigest(stated.declaredCpuType ?? 'no identity')}`;
  return {
    refusal: collateralRefusal(
      declaration.refusals.anchor,
      `no chain arrived in ${header}, so the body that arrived was weighed by nobody${words}`,
    ),
  };
}

/** The body parsed as one top-level JSON object, which is the wrapper this envelope states. */
function topLevelObject(text: string, declaration: OriginDeclaration): { readonly read: Record<string, unknown> } | { readonly refusal: CollateralRefusal } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return refused(declaration, 'the served body is not a JSON object');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return refused(declaration, 'the served body is not a JSON object');
  }
  return { read: parsed as Record<string, unknown> };
}

/**
 * Every top-level member of the body text, as the name it spells and the exact substring it holds.
 *
 * A brace-and-string walk, not a regex over unbounded JSON: it tracks nesting so a member of a member is never
 * mistaken for the wrapper's own, and it steps over a string without letting an escaped quote end one. The
 * substrings come back as they sit in the text, byte for byte, because the span as it arrived is the only
 * sequence the measured signature holds over. A text this walk cannot finish is returned as far as it got,
 * which is the whole answer for the only body that can reach it: the caller has already had the same text
 * parsed as one object, so a wrapper that will not walk is a wrapper that will not be read either.
 */
function topMembers(text: string): readonly { readonly name: string; readonly span: string }[] {
  const found: { name: string; span: string }[] = [];
  let at = skipSpace(text, 0);
  if (text.charAt(at) !== '{') {
    return found;
  }
  at = skipSpace(text, at + 1);
  while (at < text.length) {
    if (text.charAt(at) === '}') {
      return found;
    }
    const key = readString(text, at);
    if (key === null) {
      return found;
    }
    const colon = skipSpace(text, key.next);
    if (text.charAt(colon) !== ':') {
      return found;
    }
    const start = skipSpace(text, colon + 1);
    const end = endOfValue(text, start);
    if (end === null) {
      return found;
    }
    found.push({ name: key.value, span: text.slice(start, end) });
    at = skipSpace(text, end);
    if (text.charAt(at) === ',') {
      at = skipSpace(text, at + 1);
      continue;
    }
    return found;
  }
  return found;
}

/**
 * The one span a wrapper holds for `member`, or the refusal that says which way it fell short.
 *
 * A name written twice is refused rather than resolved: one of the two would be the bytes the signature is
 * taken over and the other the object the document is read out of, and which one a parser keeps is the vendor's
 * habit, not a rule this path can state about the bytes it signed.
 */
function memberSpan(text: string, member: string, declaration: OriginDeclaration): { readonly text: string } | { readonly refusal: CollateralRefusal } {
  const found = topMembers(text).filter((one) => one.name === member).map((one) => one.span);
  if (found.length === 0) {
    return refused(declaration, `the served body carries no ${member} member`);
  }
  if (found.length > 1) {
    return refused(declaration, `the served body carries ${member} twice, so one of the two would be believed and the other read`);
  }
  return { text: found[0] as string };
}

/**
 * One top-level member read as the string it holds, for the members that are values rather than signed bytes.
 *
 * The document member is taken as a span because those bytes are what the signature is taken over; this member
 * is not, and a string's span carries its quotes, so hex between two of them is 130 characters and not the 128
 * this envelope states. Both are found by the same walk, so both are refused when the name is written twice.
 */
function memberString(text: string, member: string, declaration: OriginDeclaration): { readonly value: string } | { readonly refusal: CollateralRefusal } {
  const span = memberSpan(text, member, declaration);
  if ('refusal' in span) {
    return span;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(span.text);
  } catch {
    parsed = undefined;
  }
  return typeof parsed === 'string'
    ? { value: parsed }
    : refused(declaration, `the ${member} member is not spelled as a JSON string`);
}

function skipSpace(text: string, at: number): number {
  let position = at;
  while (position < text.length && ' \t\n\r'.includes(text.charAt(position))) {
    position += 1;
  }
  return position;
}

/** A JSON string starting at `at`, read with its escapes, as its text and the position after its close. */
function readString(text: string, at: number): { readonly value: string; readonly next: number } | null {
  if (text.charAt(at) !== '"') {
    return null;
  }
  let position = at + 1;
  while (position < text.length) {
    const one = text.charAt(position);
    if (one === '\\') {
      position += 2;
      continue;
    }
    if (one === '"') {
      let parsed: unknown;
      try {
        parsed = JSON.parse(text.slice(at, position + 1));
      } catch {
        return null;
      }
      return typeof parsed === 'string' ? { value: parsed, next: position + 1 } : null;
    }
    position += 1;
  }
  return null;
}

/**
 * The position after the value starting at `at`, or null where none ends.
 *
 * Objects and arrays are walked by depth so a brace inside a string cannot end one, strings are read by the one
 * rule that knows escapes, and everything else is the literal run to the next delimiter. The span this returns
 * is returned as it sits in the text, with no whitespace folded and no key reordered.
 */
function endOfValue(text: string, at: number): number | null {
  const first = text.charAt(at);
  if (first === '{' || first === '[') {
    const close = first === '{' ? '}' : ']';
    let depth = 0;
    let position = at;
    while (position < text.length) {
      const one = text.charAt(position);
      if (one === '"') {
        const read = readString(text, position);
        if (read === null) {
          return null;
        }
        position = read.next;
        continue;
      }
      if (one === first) {
        depth += 1;
      } else if (one === close) {
        depth -= 1;
        if (depth === 0) {
          return position + 1;
        }
      } else if (first === '{' && one === '[') {
        const nested = endOfValue(text, position);
        if (nested === null) {
          return null;
        }
        position = nested;
        continue;
      }
      position += 1;
    }
    return null;
  }
  if (first === '"') {
    const read = readString(text, at);
    return read === null ? null : read.next;
  }
  if (':,{}[]'.includes(first) || first === '') {
    return null;
  }
  let position = at;
  while (position < text.length && !',}]\r\n\t '.includes(text.charAt(position))) {
    position += 1;
  }
  return position === at ? null : position;
}

function refused(declaration: OriginDeclaration, why: string): { readonly refusal: CollateralRefusal } {
  return { refusal: collateralRefusal(declaration.refusals.envelope, why) };
}
