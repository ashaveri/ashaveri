import { describe, expect, it } from 'vitest';
import { sha384 } from '@noble/hashes/sha2.js';
import {
  INTEL_PCK_CRL,
  INTEL_TCB_INFO,
  NVIDIA_RIM,
  ORIGIN_DECLARATIONS,
  appraiseCollateral,
  collateralCacheKey,
  readRimManifest,
  requestUrl,
  type CollateralErrorCode,
  type CollateralQuery,
  type CollateralRefusal,
  type CollateralTransport,
  type OriginDeclaration,
  type RimReadOutcome,
} from '../src/index.js';
import { fromBase64, sha256Hex, utf8 } from '../src/bytes.js';
import { opaqueManifest, writeRimWrapper } from './rim-writer.js';
import { certificateElement, rimChain, rimManifest, RIM_WITHIN } from './rim-document-writer.js';

/**
 * What the RIM reader answers, and what it refuses.
 *
 * The wrapper is the half of a RIM answer this package has always weighed: the bytes in `rim` decode as base64
 * and hash to the digest the same body names, and the id the answer carries is the one the question asked for.
 * The manifest inside it is weighed now, for the `TCG` form the profile names, and that is a signature taken
 * over canonicalized XML. The case below carries the canonical bytes of the signed element written out from the
 * canonicalization rules, with the digest beside them, so the implementation is required to agree with the
 * literal rather than the other way about, and a canonicalizer that merely passed its input through, or that
 * dropped an inherited declaration, would fail the arithmetic rather than pass it.
 *
 * No bytes of anybody's served RIM are here. The document is written by `rim-document-writer.ts` from the shape
 * the read profile states, over a chain of keys drawn in the run that asks for it, and the `CORIM` and `GENERIC`
 * forms keep the answer they always gave: the wrapper is read, and what the manifest inside it states is refused
 * beside it, because no rule for those shapes is declared here.
 */

const RIM_ID = 'NV_GPU_DRIVER_GH100_550.127.08';
const SWID = 'http://standards.iso.org/iso/19770/-2/2015/schema.xsd';
const DS = 'http://www.w3.org/2000/09/xmldsig#';
const C14N11 = 'http://www.w3.org/2006/12/xml-c14n11';
const ECDSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

/**
 * The canonical form of the fixture document with its `ds:Signature` element left out, written out by hand from
 * the rules: the declarations an element has in scope, by prefix with the default first, where no ancestor in
 * the node-set already carries them; its attributes by namespace and then by name, so `corpus`, `name`, `tagId`
 * and `version` whatever order the document wrote them in; the comment dropped; `<Meta/>` as a start tag and an
 * end tag; the `&gt;` of an attribute value as the character it names, since a closing bracket needs no
 * reference there; and the carriage return of the measured text as `&#xD;`, since line-end normalization runs
 * before parsing and a written return is not one.
 */
const CANONICAL_DOCUMENT = `<SoftwareIdentity xmlns="${SWID}" xmlns:ds="${DS}" corpus="false"`
  + ` name="GH100 > driver" tagId="${RIM_ID}" version="550.127.08"><Meta></Meta><Payload>`
  + '<Measurements>sha384 &gt; a&#xD;b</Measurements></Payload></SoftwareIdentity>';

/** The `DigestValue` the fixture carries: base64 of SHA-384 over `CANONICAL_DOCUMENT`, written in two lines. */
const DIGEST_VALUE = 'OJKJPvYS7xmVF4luzlRNI812w/QuTykUmC5BFYtdH4BynStOvP2mn8ez2/VMM18y';
const DIGEST_WRAPPED = 'OJKJPvYS7xmVF4luzlRNI812w/QuTykUmC5BFYtdH4BynStO\nvP2mn8ez2/VMM18y';

/**
 * The canonical form of the fixture's `ds:SignedInfo` taken as a subtree, with the digest written as the
 * document writes it. The element inherits both namespace declarations and renders them at its own top, because
 * none of its ancestors is in the node-set, and the declaration the document repeats on `ds:Transforms` is
 * dropped there because the element above it is in the set and already carries it.
 */
const CANONICAL_SIGNED_INFO = `<ds:SignedInfo xmlns="${SWID}" xmlns:ds="${DS}">`
  + `<ds:CanonicalizationMethod Algorithm="${C14N11}"></ds:CanonicalizationMethod>`
  + `<ds:SignatureMethod Algorithm="${ECDSA_SHA384}"></ds:SignatureMethod>`
  + '<ds:Reference URI="">'
  + '<ds:Transforms>'
  + `<ds:Transform Algorithm="${ENVELOPED}"></ds:Transform>`
  + `<ds:Transform Algorithm="${C14N11}"></ds:Transform>`
  + '</ds:Transforms>'
  + `<ds:DigestMethod Algorithm="${SHA384}"></ds:DigestMethod>`
  + `<ds:DigestValue>${DIGEST_WRAPPED}</ds:DigestValue>`
  + '</ds:Reference></ds:SignedInfo>';

/** The same element as the document spells it: short tags, quotes of both kinds, a repeated declaration. */
const SIGNED_INFO = '<ds:SignedInfo>'
  + `<ds:CanonicalizationMethod Algorithm="${C14N11}"/>`
  + `<ds:SignatureMethod Algorithm="${ECDSA_SHA384}"/>`
  + '<ds:Reference URI="">'
  + `<ds:Transforms xmlns:ds="${DS}">`
  + `<ds:Transform Algorithm="${ENVELOPED}"/>`
  + `<ds:Transform Algorithm="${C14N11}"/>`
  + '</ds:Transforms>'
  + `<ds:DigestMethod Algorithm="${SHA384}"/>`
  + `<ds:DigestValue>${DIGEST_WRAPPED}</ds:DigestValue>`
  + '</ds:Reference></ds:SignedInfo>';

const CANONICAL_SIGNED_INFO_BYTES = utf8(CANONICAL_SIGNED_INFO);

function query(over: Partial<CollateralQuery> = {}): CollateralQuery {
  return {
    origin: 'nvidia-rim',
    platform: 'sgx',
    cpuType: null,
    level: null,
    rimId: RIM_ID,
    appraisalAt: RIM_WITHIN,
    roots: [new Uint8Array([1])],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

function read(body: Uint8Array, over: Partial<CollateralQuery> = {}): RimReadOutcome {
  return readRimManifest(body, query(over), NVIDIA_RIM);
}

/** The wrapper a route would answer with for this manifest, stating its digest over its own bytes. */
function wrapperFor(document: string, over: Parameters<typeof writeRimWrapper>[0] = {}): Uint8Array {
  return writeRimWrapper({ rim: utf8(document), id: RIM_ID, ...over });
}

/** A manifest in the profile's shape, pinned to the root its own chain ends at. */
function manifest(over: Parameters<typeof rimManifest>[0] = {}): ReturnType<typeof rimManifest> {
  return rimManifest({ signedInfo: SIGNED_INFO, signedInfoBytes: CANONICAL_SIGNED_INFO_BYTES, ...over });
}

/** Reads a manifest of this shape under the question the case asks. */
function readManifest(over: Partial<CollateralQuery> = {}, built: Parameters<typeof rimManifest>[0] = {}): RimReadOutcome {
  const document = manifest(built);
  return read(wrapperFor(document.document), { roots: [document.rootDer], ...over });
}

function refusalOf(outcome: RimReadOutcome): CollateralRefusal {
  if (!('refusal' in outcome)) {
    throw new Error('the answer carried no refusal');
  }
  return outcome.refusal;
}

function codeOf(outcome: RimReadOutcome): CollateralErrorCode {
  return refusalOf(outcome).code;
}

function why(outcome: RimReadOutcome): string {
  return refusalOf(outcome).detail;
}

/** The text outside the `ds:Signature` element, which is what a whole-document reference digest covers. */
function outsideSignature(document: string): string {
  return document.replace(/<ds:Signature xmlns:ds="http:\/\/www\.w3\.org\/2000\/09\/xmldsig#">[\s\S]*<\/ds:Signature>/u, '');
}

function silence(): CollateralTransport {
  return async () => {
    throw new Error('a transport was asked');
  };
}

describe('the RIM wrapper reader', () => {
  it('reads a wrapper whose manifest it cannot weigh and pairs the read with the refusal', () => {
    const manifest = opaqueManifest();
    const outcome = read(writeRimWrapper({ id: RIM_ID, rim: manifest, format: 'CORIM' }));
    if (!('read' in outcome)) {
      throw new Error(`the wrapper was refused: ${why(outcome)}`);
    }
    expect(outcome.read.id).toBe(RIM_ID);
    expect(outcome.read.format).toBe('CORIM');
    expect(outcome.read.lastUpdated).toBe('2026-09-01T00:00:00Z');
    expect(outcome.read.rim).toEqual(manifest);
    expect(outcome.read.digest).toBe(sha256Hex(manifest));
    expect(outcome.read.blobs).toHaveLength(1);
    expect(refusalOf(outcome).code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(refusalOf(outcome).detail).toContain('CORIM');
  });

  it('keeps the manifest bytes as the wrapper carried them and hashes them as they arrived', () => {
    const manifest = new Uint8Array(Array.from({ length: 300 }, (_one, index) => index % 251));
    const outcome = read(writeRimWrapper({ rim: manifest, id: RIM_ID, format: 'GENERIC' }));
    if (!('read' in outcome)) throw new Error('the wrapper was refused');
    expect(outcome.read.rim).toEqual(manifest);
    expect(outcome.read.digest).toBe(sha256Hex(manifest));
    expect(codeOf(outcome)).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
  });

  it('refuses a TCG manifest that is not the document element the format names', () => {
    const outcome = read(writeRimWrapper({ rim: opaqueManifest(), id: RIM_ID }));
    expect(codeOf(outcome)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect('read' in outcome).toBe(false);
  });

  it('refuses a wrapper whose manifest is not the bytes its own digest names', () => {
    const outcome = read(writeRimWrapper({ id: RIM_ID, digest: sha256Hex(new Uint8Array([1, 2, 3])) }));
    expect(codeOf(outcome)).toBe('COLLATERAL_IDENTITY_MISMATCH');
    expect('read' in outcome).toBe(false);
    expect(why(outcome)).toContain('hashes to');
  });

  it('names the manifest the answer carries when it is not the one the question asked for', () => {
    const outcome = read(writeRimWrapper({ id: 'NVIDIA-SBIOS-another-rim' }));
    expect(codeOf(outcome)).toBe('COLLATERAL_IDENTITY_MISMATCH');
    expect(refusalOf(outcome).missing).toEqual(['rimId']);
    expect(why(outcome)).toContain('NVIDIA-SBIOS-another-rim');
  });

  it('carries no id comparison when the question names none, because nothing was stated to compare against', () => {
    const outcome = read(writeRimWrapper({ id: 'whatever-rim', format: 'CORIM' }), { rimId: null });
    if (!('read' in outcome)) throw new Error(`a question naming no id was refused at the identity: ${why(outcome)}`);
    expect(outcome.read.id).toBe('whatever-rim');
  });

  it('reads the members the route carries that this path does not weigh, and does not require them', () => {
    const withUnread = new TextEncoder().encode(JSON.stringify({
      $schema: 'https://rim.attestation.nvidia.com/schema',
      id: RIM_ID,
      message: 'The RIM was found',
      request_id: 'dcb40a1c-0000-0000-0000-000000000000',
      rim_format: 'CORIM',
      last_updated: '2024-11-19T14:25:57.236Z',
      rim: 'aGVsbG8=',
      sha256: sha256Hex(utf8('hello')),
    }));
    const outcome = read(withUnread);
    if (!('read' in outcome)) throw new Error(`a wrapper carrying members this path does not read was refused: ${why(outcome)}`);
    expect(outcome.read.id).toBe(RIM_ID);
    const without = read(writeRimWrapper({ id: RIM_ID, rim: utf8('hello'), format: 'CORIM', digest: sha256Hex(utf8('hello')) }));
    if (!('read' in without)) throw new Error(`a wrapper carrying none of those members was refused: ${why(without)}`);
    expect(without.read.id).toBe(RIM_ID);
  });

  it('refuses a format name outside the three the reference states rather than sorting it into one', () => {
    const outcome = read(writeRimWrapper({ id: RIM_ID, format: 'SWID' }));
    expect(codeOf(outcome)).toBe('COLLATERAL_STATUS_UNSUPPORTED');
    expect(why(outcome)).toContain('SWID');
    expect(why(outcome)).toContain('TCG, CORIM, GENERIC');
  });

  it('refuses a wrapper that carries no member the reader reads, one member at a time', () => {
    for (const member of ['id', 'rim_format', 'last_updated', 'rim', 'sha256']) {
      const outcome = read(writeRimWrapper({ id: RIM_ID, notText: [], omit: [member] }));
      expect(codeOf(outcome), member).toBe('COLLATERAL_BLOB_UNREADABLE');
      expect(why(outcome), member).toContain(member);
    }
  });

  it('refuses a member that is present but not the text the wrapper states it as', () => {
    for (const member of ['id', 'rim_format', 'last_updated', 'rim', 'sha256']) {
      const outcome = read(writeRimWrapper({ id: RIM_ID, notText: [member] }));
      expect(codeOf(outcome), member).toBe('COLLATERAL_BLOB_UNREADABLE');
      expect(why(outcome), member).toContain(member);
    }
  });

  it('refuses a digest that is not a sha256 and a manifest that is not base64, as shapes rather than as mismatches', () => {
    const short = read(writeRimWrapper({ id: RIM_ID, digest: 'abcd' }));
    expect(codeOf(short)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(why(short)).toContain('64 hex characters');

    const wrapped = read(writeRimWrapper({ id: RIM_ID, rimText: 'data:application/xml;base64,AAAA' }));
    expect(codeOf(wrapped)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(why(wrapped)).toContain('base64');
  });

  it('refuses a body that is not a wrapper at all, and one that is not text', () => {
    for (const body of [writeRimWrapper({ raw: 'not json' }), writeRimWrapper({ raw: '[1,2]' }), Uint8Array.from([0x30, 0x82, 0xff])]) {
      const outcome = read(body);
      expect(codeOf(outcome)).toBe('COLLATERAL_BLOB_UNREADABLE');
    }
    const empty = read(new Uint8Array(0));
    expect(codeOf(empty)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(why(empty)).toContain('empty');

    const oversize = read(writeRimWrapper({ id: RIM_ID, rim: new Uint8Array(NVIDIA_RIM.maxResponseBytes + 1) }));
    expect(codeOf(oversize)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(why(oversize)).toContain(String(NVIDIA_RIM.maxResponseBytes));
  });

  it('refuses the wrapper of an origin whose answer it is not, naming the shape that arrived', () => {
    for (const declaration of [INTEL_TCB_INFO, INTEL_PCK_CRL, ORIGIN_DECLARATIONS['amd-kds']]) {
      const outcome = readRimManifest(writeRimWrapper(), query({ origin: declaration.name }), declaration);
      expect(codeOf(outcome), declaration.name).toBe('COLLATERAL_BLOB_UNREADABLE');
      expect(why(outcome), declaration.name).toContain(declaration.answer);
    }
  });

  it('refuses a declaration stating the RIM shape beside a reader that names none', () => {
    const declaredOnly: OriginDeclaration = {
      ...NVIDIA_RIM,
      reader: { as: 'declared-only', lacks: 'an XML digital-signature reader for the manifest the wrapper carries' },
    };
    const outcome = readRimManifest(writeRimWrapper({ id: RIM_ID }), query(), declaredOnly);
    expect(codeOf(outcome)).toBe('COLLATERAL_ORIGIN_UNSUPPORTED');
    expect('read' in outcome).toBe(false);
    expect(why(outcome)).toContain(declaredOnly.answer);
  });
});

describe('the derivation this suite holds the reader to', () => {
  it('states the digest as the hash of the canonical document that was written out', () => {
    expect(Buffer.from(sha384(utf8(CANONICAL_DOCUMENT))).toString('base64')).toBe(DIGEST_VALUE);
  });

  it('writes the digest in two lines, which is the spelling the served profile writes it in', () => {
    expect(DIGEST_WRAPPED.split('\n')).toHaveLength(2);
    expect(fromBase64(DIGEST_WRAPPED)).toBeNull();
    expect(fromBase64(DIGEST_WRAPPED.replace(/\n/gu, ''))).not.toBeNull();
  });

  it('carries the two declarations a subtree inherits, and no short tag', () => {
    expect(CANONICAL_SIGNED_INFO.startsWith(`<ds:SignedInfo xmlns="${SWID}" xmlns:ds="${DS}">`)).toBe(true);
    expect(CANONICAL_SIGNED_INFO.match(/ xmlns:/gu)).toHaveLength(1);
    expect(CANONICAL_SIGNED_INFO.match(/ xmlns="/gu)).toHaveLength(1);
    expect(CANONICAL_SIGNED_INFO).not.toContain('/>');
  });

  it('orders the four attributes of the document element by name where the document did not', () => {
    expect(CANONICAL_DOCUMENT.indexOf('corpus')).toBeLessThan(CANONICAL_DOCUMENT.indexOf('name="GH100'));
    expect(CANONICAL_DOCUMENT.indexOf('tagId')).toBeLessThan(CANONICAL_DOCUMENT.indexOf('version='));
  });
});

describe('the TCG manifest reader', () => {
  it('weighs a manifest whose signature holds, and answers with no refusal beside it', () => {
    const outcome = readManifest();
    if (!('read' in outcome)) throw new Error(`the manifest was refused: ${why(outcome)}`);
    expect('refusal' in outcome).toBe(false);
    expect(outcome.read.format).toBe('TCG');
    expect(outcome.read.tagId).toBe(RIM_ID);
    expect(outcome.read.anchorDigest).not.toBeNull();
  });

  it('names the anchor the chain ended on and carries the certificate bytes beside the wrapper', () => {
    const document = manifest();
    const body = wrapperFor(document.document);
    const outcome = read(body, { roots: [document.rootDer] });
    if (!('read' in outcome)) throw new Error(`the manifest was refused: ${why(outcome)}`);
    expect(outcome.read.anchorDigest).toBe(sha256Hex(document.rootDer));
    expect(outcome.read.blobs).toEqual([body, ...document.chain.map((link) => link.der)]);
  });

  it('weighs the same information from a document that spells it another way', () => {
    const reshuffled = SIGNED_INFO
      .replace('<ds:SignedInfo>', '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">')
      .replace(`<ds:Transforms xmlns:ds="${DS}">`, '<ds:Transforms>');
    const document = manifest({ signedInfo: reshuffled });
    const text = document.document
      .replace('<Meta/>', '<Meta></Meta>')
      .replace("tagId='NV_GPU_DRIVER_GH100_550.127.08' version='550.127.08'", "version='550.127.08' tagId='NV_GPU_DRIVER_GH100_550.127.08'")
      .replace("xmlns='http://standards.iso.org/iso/19770/-2/2015/schema.xsd' xmlns:ds='http://www.w3.org/2000/09/xmldsig#'", `xmlns="${SWID}" xmlns:ds="${DS}"`);
    const outcome = read(wrapperFor(text), { roots: [document.rootDer] });
    if (!('read' in outcome)) throw new Error(`a re-spelled document was refused: ${why(outcome)}`);
    expect(outcome.read.tagId).toBe(RIM_ID);
  });

  it('refuses a manifest that is not well-formed XML rather than crashing on it', () => {
    for (const broken of [
      'ashaveri-synthetic-rim-manifest-body',
      `<SoftwareIdentity xmlns="${SWID}">`,
      `<SoftwareIdentity xmlns="${SWID}"></Mismatched>`,
      `<SoftwareIdentity xmlns="${SWID}"><a attr="unclosed"></a></SoftwareIdentity>`,
      `<SoftwareIdentity xmlns="${SWID}">&undeclared;</SoftwareIdentity>`,
    ]) {
      const outcome = read(wrapperFor(broken));
      expect(codeOf(outcome), broken.slice(0, 42)).toBe('COLLATERAL_BLOB_UNREADABLE');
      expect('read' in outcome, broken.slice(0, 42)).toBe(false);
    }
  });

  it('refuses a document type declaration before the manifest is read any further', () => {
    const outcome = readManifest({}, { prologue: '<!DOCTYPE SoftwareIdentity [<!ENTITY x "y">]>' });
    expect(codeOf(outcome)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(why(outcome)).toContain('document type declaration');
  });

  it('refuses an entity declaration carried inside the document', () => {
    const outcome = readManifest({}, { extraBody: '<!ENTITY x "y">' });
    expect(codeOf(outcome)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(why(outcome)).toContain('declaration');
  });

  it('refuses a document over the ceilings this path states', () => {
    const outcome = readManifest({}, { extraBody: '<r/>'.repeat(4100) });
    expect(codeOf(outcome)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(why(outcome)).toContain('elements');
  });

  it('refuses a second Signature element, and a SignedInfo that is not the first child of the one', () => {
    const twice = readManifest({}, { signatures: 2 });
    expect(codeOf(twice)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(why(twice)).toContain('Signature');

    const doubled = readManifest({}, { signedInfo: `${SIGNED_INFO}${SIGNED_INFO}` });
    expect(codeOf(doubled)).toBe('COLLATERAL_BLOB_UNREADABLE');

    const misplaced = readManifest({}, {
      signature: `<ds:Signature xmlns:ds="${DS}"><ds:SignatureValue>x</ds:SignatureValue>${SIGNED_INFO}</ds:Signature>`,
    });
    expect(codeOf(misplaced)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(why(misplaced)).toContain('first child');
  });

  it('refuses a Reference that is not the same-document form the profile names', () => {
    const pointing = SIGNED_INFO.replace('<ds:Reference URI="">', '<ds:Reference URI="#other">');
    const absent = SIGNED_INFO.replace('<ds:Reference URI="">', '<ds:Reference>');
    const typed = SIGNED_INFO.replace('<ds:Reference URI="">', '<ds:Reference URI="" Type="http://www.w3.org/2000/09/xmldsig#Object">');
    for (const variant of [pointing, absent, typed]) {
      const outcome = readManifest({}, { signedInfo: variant });
      expect(codeOf(outcome), variant.slice(0, 60)).toBe('COLLATERAL_STATUS_UNSUPPORTED');
      expect(why(outcome), variant.slice(0, 60)).toContain('URI');
    }
  });

  it('refuses a Transforms list that is not the two the profile states, in that order', () => {
    const noEnveloped = SIGNED_INFO.replace(`<ds:Transform Algorithm="${ENVELOPED}"/>`, '');
    const extra = SIGNED_INFO.replace('</ds:Transforms>', '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/></ds:Transforms>');
    const inverted = SIGNED_INFO.replace(
      `<ds:Transform Algorithm="${ENVELOPED}"/><ds:Transform Algorithm="${C14N11}"/>`,
      `<ds:Transform Algorithm="${C14N11}"/><ds:Transform Algorithm="${ENVELOPED}"/>`,
    );
    const comments = SIGNED_INFO.replace(`<ds:Transform Algorithm="${C14N11}"/>`, `<ds:Transform Algorithm="${C14N11}#WithComments"/>`);
    const parameters = SIGNED_INFO.replace(
      `<ds:Transform Algorithm="${C14N11}"/>`,
      `<ds:Transform Algorithm="${C14N11}"><ds:TransformationParameters><x xmlns="urn:x">1</x></ds:TransformationParameters></ds:Transform>`,
    );
    for (const variant of [noEnveloped, extra, inverted, comments, parameters]) {
      const outcome = readManifest({}, { signedInfo: variant });
      expect(codeOf(outcome), variant.slice(0, 60)).toBe('COLLATERAL_STATUS_UNSUPPORTED');
    }
    expect(why(readManifest({}, { signedInfo: extra }))).toContain('base64');
    expect(why(readManifest({}, { signedInfo: comments }))).toContain('WithComments');
  });

  it('refuses an algorithm identifier outside the set, naming the identifier it met', () => {
    const exclusive = SIGNED_INFO.replace(C14N11, 'http://www.w3.org/2001/10/xml-exc-c14n#');
    const rsa = SIGNED_INFO.replace(ECDSA_SHA384, 'http://www.w3.org/2000/09/xmldsig#rsa-sha1');
    const sha1 = SIGNED_INFO.replace(SHA384, 'http://www.w3.org/2000/09/xmldsig#sha1');
    for (const variant of [exclusive, rsa, sha1]) {
      expect(codeOf(readManifest({}, { signedInfo: variant })), variant.slice(0, 60)).toBe('COLLATERAL_STATUS_UNSUPPORTED');
    }
    expect(why(readManifest({}, { signedInfo: exclusive }))).toContain('xml-exc-c14n');
    expect(why(readManifest({}, { signedInfo: rsa }))).toContain('rsa-sha1');
  });

  it('refuses a DigestValue that is not the digest of the bytes this reader canonicalized', () => {
    const outcome = readManifest({}, { measurements: 'sha384 &gt; a &#xD;b' });
    expect(codeOf(outcome)).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(why(outcome)).toContain('digest');
    expect(why(outcome)).not.toContain('does not hold over');
  });

  it('refuses a SignatureValue that does not verify over the canonicalized SignedInfo', () => {
    const standing = manifest();
    const outcome = read(wrapperFor(standing.document), {
      roots: [standing.rootDer],
    });
    if (!('read' in outcome)) throw new Error(`the manifest was refused: ${why(outcome)}`);
    const shifted = manifest({ signedInfoBytes: utf8(`${CANONICAL_SIGNED_INFO} `) });
    const refused = read(wrapperFor(shifted.document), { roots: [shifted.rootDer] });
    expect(codeOf(refused)).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(why(refused)).toContain('does not hold over');
  });

  it('refuses a KeyInfo that carries no certificate, or more than the chain the profile states', () => {
    const document = manifest();
    const bare = document.document.replace(/<ds:X509Data>[\s\S]*?<\/ds:X509Data>/u, '<ds:X509Data></ds:X509Data>');
    const none = read(wrapperFor(bare), { roots: [document.rootDer] });
    expect(codeOf(none)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(why(none)).toContain('no certificate');
    const crowded = document.document.replace(
      '</ds:X509Data>',
      '<ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data>',
    );
    const outcome = read(wrapperFor(crowded), { roots: [document.rootDer] });
    expect(codeOf(outcome)).toBe('COLLATERAL_STATUS_UNSUPPORTED');
    expect(why(outcome)).toContain('5 certificates');
  });

  it('refuses a chain that does not reach a root the caller pinned, and a caller that pinned none', () => {
    const document = manifest();
    const none = read(wrapperFor(document.document), { roots: [] });
    expect(codeOf(none)).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    expect(why(none)).toContain('pinned none');
    const unreadable = read(wrapperFor(document.document), { roots: [new Uint8Array([1, 2, 3])] });
    expect(codeOf(unreadable)).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    expect(why(unreadable)).toContain('does not parse');
    const short = manifest({ chain: rimChain().slice(0, 3) });
    const stopped = read(wrapperFor(short.document), { roots: [short.rootDer] });
    expect(codeOf(stopped)).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    expect(why(stopped)).toContain('stops short');
  });

  it('refuses a chain that ends at the name a caller pinned without that name being signed by it', () => {
    const document = manifest();
    const other = manifest();
    const foreign = read(wrapperFor(document.document), { roots: [other.rootDer] });
    expect(codeOf(foreign)).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(why(foreign)).toContain('the certificate wearing it is not signed by that pinned copy');
  });

  it('weighs the chain at the instant the appraisal runs, and moves with it', () => {
    const document = manifest();
    const body = wrapperFor(document.document);
    const standing = read(body, { roots: [document.rootDer], appraisalAt: RIM_WITHIN });
    if (!('read' in standing)) throw new Error(`the chain was refused at the instant it stands at: ${why(standing)}`);
    const closed = read(body, { roots: [document.rootDer], appraisalAt: RIM_WITHIN + 86401 });
    expect(codeOf(closed)).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(why(closed)).toContain('validity');
    expect(why(closed)).toContain('0 of the chain');
    const middle = manifest({ chain: rimChain({ expired: 2 }) });
    const stopped = read(wrapperFor(middle.document), { roots: [middle.rootDer], appraisalAt: RIM_WITHIN });
    expect(codeOf(stopped)).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(why(stopped)).toContain('2 of the chain');
  });

  it('refuses a chain over a key the profile does not name', () => {
    const document = manifest();
    const weaker = rimChain({ curve: 'p256' });
    const swapped = document.document.replace(
      /<ds:X509Data>[\s\S]*?<\/ds:X509Data>/u,
      `<ds:X509Data>${weaker.map((link) => certificateElement(link.der)).join('')}</ds:X509Data>`,
    );
    const outcome = read(wrapperFor(swapped), { roots: [weaker[3]?.der as Uint8Array] });
    expect(codeOf(outcome)).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(why(outcome)).toContain('ec-p256');
  });

  it('refuses a certificate that is not base64, or one that does not parse', () => {
    const document = manifest();
    const broken = document.document
      .replace(/<ds:X509Certificate>[\s\S]*?<\/ds:X509Certificate>/u, '<ds:X509Certificate>not base64 !!</ds:X509Certificate>');
    expect(codeOf(read(wrapperFor(broken), { roots: [document.rootDer] }))).toBe('COLLATERAL_BLOB_UNREADABLE');
    const unparsed = document.document
      .replace(/<ds:X509Certificate>[\s\S]*?<\/ds:X509Certificate>/u, '<ds:X509Certificate>AAAA</ds:X509Certificate>');
    expect(codeOf(read(wrapperFor(unparsed), { roots: [document.rootDer] }))).toBe('COLLATERAL_BLOB_UNREADABLE');
  });

  it('binds the answer to the question by the id the wrapper states and reports the tag identity apart', () => {
    const document = manifest();
    const asked = read(wrapperFor(document.document), { rimId: 'another-manifest', roots: [document.rootDer] });
    expect(codeOf(asked)).toBe('COLLATERAL_IDENTITY_MISMATCH');
    expect(why(asked)).toContain('another-manifest');
    const renamed = read(wrapperFor(document.document, { id: 'another-handle' }), { rimId: 'another-handle', roots: [document.rootDer] });
    if (!('read' in renamed)) {
      throw new Error(`the manifest was refused for a tag identity that is not the handle it was asked by: ${why(renamed)}`);
    }
    expect(renamed.read.id).toBe('another-handle');
    expect(renamed.read.tagId).toBe(document.tagId);
  });

  it('refuses the wrapping case, where the content handed back is not the content that was signed', () => {
    const golden = manifest();
    const decoy = manifest({
      insideKeyInfo: `<SoftwareIdentity xmlns="${SWID}" tagId="a-different-device"></SoftwareIdentity>`,
    });
    expect(outsideSignature(decoy.document)).toBe(outsideSignature(golden.document));
    const outcome = read(wrapperFor(decoy.document, { id: 'a-different-device' }), {
      rimId: 'a-different-device',
      roots: [decoy.rootDer],
    });
    expect(codeOf(outcome)).toBe('COLLATERAL_STATUS_UNSUPPORTED');
    expect(why(outcome)).toContain('SoftwareIdentity');
    expect(why(outcome)).toContain('KeyInfo');
  });

  it('refuses a document that carries the identity element twice outside the signature', () => {
    const outcome = readManifest({}, {
      extraBody: `<SoftwareIdentity xmlns="${SWID}" tagId="${RIM_ID}"></SoftwareIdentity>`,
    });
    expect(codeOf(outcome)).toBe('COLLATERAL_BLOB_UNREADABLE');
    expect(why(outcome)).toContain('twice');
  });

  it('refuses a document element that is not the SWID manifest the format names', () => {
    const document = manifest();
    const wrong = document.document.replace(SWID, 'urn:elsewhere');
    const outcome = read(wrapperFor(wrong), { roots: [document.rootDer] });
    expect(codeOf(outcome)).toBe('COLLATERAL_STATUS_UNSUPPORTED');
    expect(why(outcome)).toContain('urn:elsewhere');
  });

  it('refuses to weigh a chain when the question named no instant to weigh it at', () => {
    const outcome = readManifest({ appraisalAt: null });
    expect(codeOf(outcome)).toBe('COLLATERAL_INPUT_MISSING');
    expect(refusalOf(outcome).missing).toEqual(['appraisalAt']);
  });

  it('refuses an appraisal of the RIM before anything is asked of the origin', async () => {
    const outcome = await appraiseCollateral(query(), { transport: silence() });
    expect(outcome.state).toBe('missing-context');
    if (!('refusal' in outcome)) throw new Error('the RIM answered with a verdict it cannot reach');
    expect(outcome.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    expect(outcome.refusal.detail).toContain('readRimManifest');
    expect(outcome.refusal.missing).toEqual(['level']);
    expect(outcome.collateral).toBeNull();
    expect(outcome.claim).toBeNull();
  });

  it('names the id a RIM address cannot be built without, and spells the route when it is given', () => {
    const missing = requestUrl(query({ rimId: null }), NVIDIA_RIM);
    if (typeof missing === 'string') throw new Error('a RIM address was spelled without an id');
    expect(missing.refusal.code).toBe('COLLATERAL_INPUT_MISSING');
    expect(missing.refusal.missing).toEqual(['rimId']);
    expect(requestUrl(query({ rimId: 'gpu rim/0001' }), NVIDIA_RIM)).toBe(
      'https://rim.attestation.nvidia.com/v1/rim/gpu%20rim%2F0001',
    );
  });

  it('states no record for a kept manifest, because no reader states the window it belongs to', () => {
    const key = collateralCacheKey(query(), NVIDIA_RIM);
    if (typeof key === 'string') throw new Error('a kept RIM was keyed without a window to answer for');
    expect(key.missing).toEqual([]);
    expect(key.why).toContain('no cache key yet');
  });
});
