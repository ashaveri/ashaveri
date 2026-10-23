import { sha256 } from '@noble/hashes/sha2.js';

/**
 * A writer for the JSON wrapper a RIM route answers in, so the cases in `rim.test.ts` hand the reader a real
 * answer without storing anybody's served bytes.
 *
 * The members are the ones cited beside the `nvidia-rim` declaration in `src/intel-origin.ts`: `id`,
 * `last_updated`, `message`, `request_id`, `rim`, `rim_format` and `sha256`. What the `rim` member carries is
 * deliberately opaque bytes with a label rather than a document this repository makes up: the manifest inside a
 * wrapper is signed in a form this package states no rule for reading, so a fixture that spelled SWID elements
 * would be inventing the vendor's field names while testing nothing that a reader weighs. The writer states the
 * wrapper's own digest, which is the one claim about those bytes this path establishes.
 */

export interface RimWrapperInput {
  /** The manifest id the wrapper states for itself. */
  readonly id?: string;
  /** The manifest bytes, which the wrapper carries as base64 text. */
  readonly rim?: Uint8Array;
  /** The format name the wrapper states, one of the three its reference names. */
  readonly format?: string;
  /** The `last_updated` text the wrapper states, which names no validity window. */
  readonly lastUpdated?: string;
  /** A digest other than the manifest's own, spelled as the wrapper spells a digest. */
  readonly digest?: string;
  /** The `rim` text to write verbatim, for a case that asks what a non-base64 spelling gets. */
  readonly rimText?: string;
  /** Members to leave out entirely, by the name the wrapper would have carried them under. */
  readonly omit?: readonly string[];
  /** Members to write as something other than text, by the name a case would have read them under. */
  readonly notText?: readonly string[];
  /** A body that is not the wrapper at all, written verbatim. */
  readonly raw?: string;
}

const OPAQUE_MANIFEST = new TextEncoder().encode('ashaveri-synthetic-rim-manifest-body');

/** One wrapper, in the shape its reference states, signed by nobody. */
export function writeRimWrapper(input: RimWrapperInput = {}): Uint8Array {
  if (input.raw !== undefined) {
    return new TextEncoder().encode(input.raw);
  }
  const manifest = input.rim ?? OPAQUE_MANIFEST;
  const digest = input.digest ?? toHex(sha256(manifest));
  const rimText = input.rimText ?? toBase64(manifest);
  const omit = new Set(input.omit ?? []);
  const notText = new Set(input.notText ?? []);
  const members: Record<string, unknown> = {};
  if (!omit.has('id')) {
    members['id'] = notText.has('id') ? 7 : input.id ?? 'NVIDIA-SBIOS-gpu-rim-0001';
  }
  if (!omit.has('rim_format')) {
    members['rim_format'] = notText.has('rim_format') ? true : input.format ?? 'TCG';
  }
  if (!omit.has('last_updated')) {
    members['last_updated'] = notText.has('last_updated') ? [] : input.lastUpdated ?? '2026-09-01T00:00:00Z';
  }
  if (!omit.has('rim')) {
    members['rim'] = notText.has('rim') ? {} : rimText;
  }
  if (!omit.has('sha256')) {
    members['sha256'] = notText.has('sha256') ? 1.5 : digest;
  }
  return new TextEncoder().encode(JSON.stringify(members));
}

/** The manifest bytes a wrapper written with no `rim` override carries. */
export function opaqueManifest(): Uint8Array {
  return OPAQUE_MANIFEST;
}

const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function toBase64(bytes: Uint8Array): string {
  const text: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 3) {
    const chunk = bytes.subarray(offset, Math.min(offset + 3, bytes.length));
    const value = (chunk[0] ?? 0) << 16 | (chunk[1] ?? 0) << 8 | (chunk[2] ?? 0);
    text.push(
      BASE64[(value >> 18) & 0x3f] as string,
      BASE64[(value >> 12) & 0x3f] as string,
      chunk.length > 1 ? BASE64[(value >> 6) & 0x3f] as string : '=',
      chunk.length > 2 ? BASE64[value & 0x3f] as string : '=',
    );
  }
  return text.join('');
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
