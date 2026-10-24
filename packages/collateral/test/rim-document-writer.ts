import { p384 } from '@noble/curves/nist.js';
import { sha384 } from '@noble/hashes/sha2.js';
import { secondsOf, testChain, type ChainCertificate, type FixtureCurve } from '@ashaveri/fixtures';
import { utf8 } from '../src/bytes.js';

/**
 * A writer for the `TCG` form of a RIM manifest, so the cases in `rim.test.ts` hand the reader a signed SWID
 * document without storing anybody's served bytes.
 *
 * Nothing here canonicalizes. The bytes a signature is taken over are handed in by the case that asks about
 * them, spelled out from the canonicalization rules, and this file writes them into a document and signs them.
 * That separation is the point: a writer that canonicalized with the code the reader uses would let the two
 * agree on a wrong rule, and a suite built on that agreement would prove nothing about a manifest nobody here
 * signed.
 *
 * The shape is the one the read profile states: a document element named `SoftwareIdentity` in the SWID
 * namespace, one `ds:Signature` carrying one `ds:SignedInfo`, a `ds:SignatureValue` and a `ds:KeyInfo` whose
 * `ds:X509Data` holds the chain leaf-first. The base64 of each certificate and of the signature is written in
 * lines, as the served profile writes it, so a reader that demanded one unbroken run of characters would be
 * refusing the shape rather than reading it.
 */

const SWID = 'http://standards.iso.org/iso/19770/-2/2015/schema.xsd';
const DS = 'http://www.w3.org/2000/09/xmldsig#';

/** The instant the default chain stands at, one day before its foot stops standing. */
export const RIM_WITHIN = secondsOf('2026-10-27T00:00:00Z');

/** The instants each link of a four-deep chain stops standing, leaf first, with the foot one day after those. */
const RIM_EXPIRY = [
  secondsOf('2026-10-28T00:00:00Z'),
  secondsOf('2027-04-30T00:00:00Z'),
  secondsOf('2033-05-11T00:00:00Z'),
  secondsOf('2053-03-08T00:00:00Z'),
];

/** The names of a chain of the length asked for, leaf first, the foot a signer and every link above it an authority. */
function namesOf(length: number): readonly string[] {
  return Array.from({ length }, (_one, index) => {
    if (index === 0) {
      return 'Ashaveri Test RIM Signer';
    }
    return index === length - 1 ? 'Ashaveri Test RIM Root CA' : `Ashaveri Test RIM Level ${String(length - index - 1)}`;
  });
}

/**
 * A leaf-first P-384 chain of the length a case names, with one link's expiry moved before the instant the
 * default chain stands at.
 *
 * The link is named by its position from the foot because the fact a case asks is which link stopped standing,
 * and where a walk had got to when it met it.
 */
export function rimChain(input: { readonly length?: number; readonly expired?: number; readonly curve?: FixtureCurve } = {}): readonly ChainCertificate[] {
  const length = input.length ?? 4;
  const names = namesOf(length);
  const notAfter = names.map((_one, index) => RIM_EXPIRY[RIM_EXPIRY.length - length + index] as number);
  if (input.expired !== undefined) {
    notAfter[input.expired] = RIM_WITHIN - 1;
  }
  return testChain({ names, notAfter, curve: input.curve ?? 'p384', notBefore: secondsOf('2023-03-16T00:00:00Z') });
}

export interface RimManifestInput {
  /** The `ds:SignedInfo` element as the document spells it, digest text and all. */
  readonly signedInfo?: string;
  /** The canonical bytes the signature is taken over, written out by the case that asks for them. */
  readonly signedInfoBytes?: Uint8Array;
  /** The whole `ds:Signature` element, when a case writes one instead of the one this file spells. */
  readonly signature?: string;
  /** The tag identity the document element states for itself. */
  readonly tagId?: string;
  /** The text of the measured content the signed body carries. */
  readonly measurements?: string;
  /** The chain the `KeyInfo` presents. The default four, when a case has no view of its own. */
  readonly chain?: readonly ChainCertificate[];
  /** Extra markup written inside the `KeyInfo`, which is content the signature does not cover. */
  readonly insideKeyInfo?: string;
  /** How many times the `ds:Signature` element is written into the signed body. */
  readonly signatures?: number;
  /** Markup written after the measured content inside the signed body, for a case that counts elements. */
  readonly extraBody?: string;
  /** Markup written before the document element, for a case that asks what a declaration gets. */
  readonly prologue?: string;
}

export interface RimManifest {
  /** The manifest as the wrapper carries it: the text a reader is asked to weigh. */
  readonly document: string;
  /** The chain the document presents, leaf first. */
  readonly chain: readonly ChainCertificate[];
  /** The self-signed link, which is the one a caller pins. */
  readonly rootDer: Uint8Array;
  /** Signs these bytes with the leaf key this manifest was built under, in the width the profile carries. */
  readonly signatureOver: (bytes: Uint8Array) => string;
  readonly tagId: string;
}

/** One manifest, signed by the chain it presents, over the bytes the case named. */
export function rimManifest(input: RimManifestInput = {}): RimManifest {
  const chain = input.chain ?? rimChain();
  const leaf = chain[0] as ChainCertificate;
  const signatureOver = (bytes: Uint8Array): string => wrap(toBase64(p384.sign(sha384(bytes), leaf.secret).toBytes('compact')));
  const tagId = input.tagId ?? 'NV_GPU_DRIVER_GH100_550.127.08';
  const certificates = chain.map((link) => certificateElement(link.der)).join('');
  const signature = input.signature ?? `<ds:Signature xmlns:ds="${DS}">${String(input.signedInfo ?? '')}`
    + `<ds:SignatureValue>${signatureOver(input.signedInfoBytes ?? new Uint8Array(0))}</ds:SignatureValue>`
    + `<ds:KeyInfo><ds:X509Data>${certificates}${String(input.insideKeyInfo ?? '')}</ds:X509Data></ds:KeyInfo>`
    + '</ds:Signature>';
  const document = `<SoftwareIdentity xmlns='${SWID}' xmlns:ds='${DS}' tagId='${tagId}' version='550.127.08'`
    + " name='GH100 &gt; driver' corpus='false'><Meta/><Payload>"
    + '<!--a comment the signature never covered-->'
    + signature.repeat(input.signatures ?? 1)
    + `<Measurements>${String(input.measurements ?? 'sha384 &gt; a&#xD;b')}</Measurements>${String(input.extraBody ?? '')}</Payload></SoftwareIdentity>`;
  return {
    document: `${String(input.prologue ?? '')}${document}`,
    chain,
    rootDer: (chain[chain.length - 1] as ChainCertificate).der,
    signatureOver,
    tagId,
  };
}

/** The manifest bytes a wrapper carries for this document, as the reader receives them. */
export function manifestBytes(manifest: RimManifest): Uint8Array {
  return utf8(manifest.document);
}

/** One `ds:X509Certificate` element, its base64 written in lines as the served profile writes it. */
export function certificateElement(der: Uint8Array): string {
  return `<ds:X509Certificate>${wrap(toBase64(der))}</ds:X509Certificate>`;
}

/** Base64 in 64-character lines, the spelling a served manifest carries its values in. */
export function wrap(base64: string): string {
  const lines: string[] = [];
  for (let offset = 0; offset < base64.length; offset += 64) {
    lines.push(base64.slice(offset, offset + 64));
  }
  return lines.join('\n');
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}
