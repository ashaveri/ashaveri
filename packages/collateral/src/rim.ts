import { sha256 } from '@noble/hashes/sha2.js';
import { fromBase64, toHex } from './bytes.js';
import { collateralRefusal, quoteOrDigest, type CollateralRefusal } from './errors.js';
import { hasReader, isRimDeclaration, type OriginDeclaration } from './intel-origin.js';
import { decodeText } from './read.js';
import type { CollateralQuery, RimManifest } from './types.js';

/**
 * What a RIM answer states about itself, beside the refusal that says none of it was weighed.
 *
 * The two always travel together for an answer that parses: the wrapper is read, and the manifest inside it is
 * signed in a form this package states no rule for canonicalizing. A caller that took one half of this outcome
 * as a verdict would be reading a statement about an HTTP answer as a statement about a device, so the pairing
 * is the shape rather than a courtesy.
 */
export type RimReadOutcome = { readonly read: RimManifest; readonly refusal: CollateralRefusal } | { readonly refusal: CollateralRefusal };

/** The three formats NVIDIA's reference names for the member, stated apart so a refusal can quote the one met. */
const FORMATS = ['TCG', 'CORIM', 'GENERIC'];

/**
 * Reads the JSON wrapper a RIM route answers in, and refuses the manifest it carries.
 *
 * The wrapper's members are the ones cited beside the declaration in `intel-origin.ts`: `id`, `last_updated`,
 * `rim`, `rim_format` and `sha256`. What this path establishes about them is only what the wrapper states
 * about itself: that the bytes in `rim` decode as base64 and hash to the digest the same body names, and that
 * the id the answer carries is the one the question asked for. A digest is not a signature: it says these are
 * the bytes the service meant to send, and nothing about who signed them or what the manifest stands for.
 *
 * What stops a manifest from being read is canonicalization rather than parsing. The `TCG` form is SWID XML
 * whose signature is taken over a canonicalized element, and no XML digital-signature canonicalization exists
 * in this package's dependencies, so no measurement inside a manifest reaches a verdict here; the `CORIM` and
 * `GENERIC` forms name a shape this path has no rule for either, and none of the three is settled from an
 * answer observed here, because no served RIM body is committed and the route sits behind an account. The
 * refusal therefore says which form the service named and what a reader would still need, rather than sorting
 * an unread document into the nearer one.
 *
 * The `rim` member is read as the standard base64 text its reference spells it as, and no other spelling is
 * stripped rather than refused: a `data:` prefix or a line-wrapped body is an answer this path has not seen and
 * would be guessing at, which is the refusal for a wrapper that carries no readable manifest rather than a
 * quieter one.
 */
export function readRimManifest(body: Uint8Array, query: CollateralQuery, declaration: OriginDeclaration): RimReadOutcome {
  const wrong = envelopeRefusal(declaration);
  if (wrong !== null) {
    return { refusal: wrong };
  }
  if (body.byteLength === 0) {
    return { refusal: unreadable(declaration, 'the answer is empty') };
  }
  if (body.byteLength > declaration.maxResponseBytes) {
    return {
      refusal: unreadable(
        declaration,
        `the answer is ${String(body.byteLength)} bytes, over the ${String(declaration.maxResponseBytes)} this path reads`,
      ),
    };
  }
  const text = decodeText(body, declaration);
  if (typeof text !== 'string') {
    return { refusal: text.refusal };
  }
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    return { refusal: unreadable(declaration, 'the answer is not a JSON object') };
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    return { refusal: unreadable(declaration, 'the answer is not a JSON object') };
  }
  const stated = payload as Record<string, unknown>;
  const id = stringMember(stated, 'id', declaration);
  if ('refusal' in id) {
    return { refusal: id.refusal };
  }
  const format = stringMember(stated, 'rim_format', declaration);
  if ('refusal' in format) {
    return { refusal: format.refusal };
  }
  const lastUpdated = stringMember(stated, 'last_updated', declaration);
  if ('refusal' in lastUpdated) {
    return { refusal: lastUpdated.refusal };
  }
  const encoded = stringMember(stated, 'rim', declaration);
  if ('refusal' in encoded) {
    return { refusal: encoded.refusal };
  }
  const statedDigest = stringMember(stated, 'sha256', declaration);
  if ('refusal' in statedDigest) {
    return { refusal: statedDigest.refusal };
  }
  if (!FORMATS.includes(format.value)) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.statusUnknown,
        `the wrapper names the manifest format ${quoteOrDigest(format.value)}, which is none of ${FORMATS.join(', ')}`,
      ),
    };
  }
  if (query.rimId !== null && query.rimId !== undefined && query.rimId !== id.value) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.identity,
        `the answer carries the manifest ${quoteOrDigest(id.value)} and the question asked for ${quoteOrDigest(query.rimId)}`,
        ['rimId'],
      ),
    };
  }
  const digest = digestOf(statedDigest.value, declaration);
  if ('refusal' in digest) {
    return { refusal: digest.refusal };
  }
  const manifest = fromBase64(encoded.value);
  if (manifest === null) {
    return { refusal: unreadable(declaration, 'the rim member is not standard base64 text') };
  }
  const actual = toHex(sha256(manifest));
  if (actual !== digest.value) {
    return {
      refusal: collateralRefusal(
        declaration.refusals.identity,
        `the manifest the wrapper carries hashes to ${actual} and the wrapper states ${digest.value}`,
        [],
      ),
    };
  }
  return {
    read: { id: id.value, format: format.value, lastUpdated: lastUpdated.value, rim: manifest, digest: actual, blobs: [body] },
    refusal: collateralRefusal(
      declaration.refusals.signature,
      `the wrapper is read and its own digest holds, and the ${format.value} manifest inside it is signed over a canonicalized element this path states no rule for weighing`,
    ),
  };
}

/** The one refusal shape this reader can hand for a declaration it has no arm for. */
function envelopeRefusal(declaration: OriginDeclaration): CollateralRefusal | null {
  if (isRimDeclaration(declaration)) {
    return null;
  }
  return collateralRefusal(
    hasReader(declaration) ? 'COLLATERAL_BLOB_UNREADABLE' : 'COLLATERAL_ORIGIN_UNSUPPORTED',
    `${declaration.name} answers as ${declaration.answer} and this reader weighs a RIM wrapper alone`,
  );
}

function stringMember(
  owner: Record<string, unknown>,
  member: string,
  declaration: OriginDeclaration,
): { readonly value: string } | { readonly refusal: CollateralRefusal } {
  const value = owner[member];
  if (typeof value !== 'string' || value.length === 0) {
    return { refusal: unreadable(declaration, `the wrapper carries no ${member} text`) };
  }
  return { value };
}

/** A digest the wrapper states, as the hex it means rather than as the case it was typed in. */
function digestOf(
  text: string,
  declaration: OriginDeclaration,
): { readonly value: string } | { readonly refusal: CollateralRefusal } {
  if (!/^[0-9a-fA-F]{64}$/u.test(text)) {
    return { refusal: unreadable(declaration, 'the sha256 member is not 64 hex characters') };
  }
  return { value: text.toLowerCase() };
}

function unreadable(declaration: OriginDeclaration, why: string): CollateralRefusal {
  return collateralRefusal(declaration.refusals.envelope, why);
}
