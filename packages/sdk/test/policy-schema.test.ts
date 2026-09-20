import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { Ajv2020, type ValidateFunction } from 'ajv/dist/2020.js';
import {
  PINNED_TEXT_PATTERN,
  SdkError,
  parsePolicyFile,
  policyFileDigest,
} from '../src/index.js';

const schemaPath = fileURLToPath(new URL('../schemas/policy-v1.schema.json', import.meta.url));
const readSchema = (): object => JSON.parse(readFileSync(schemaPath, 'utf8')) as object;

/**
 * Compiles the policy schema with Ajv's strict mode on, so a keyword this schema does not define
 * fails at compile time instead of being ignored. This is the mechanism `receipt-v1.schema.json` is
 * held to its codec by, copied here unchanged: the schema is a published contract, the loader is the
 * implementation, and one test suite decides whether the two still say the same thing.
 */
function compile(schema: object): ValidateFunction<unknown> {
  const ajv = new Ajv2020({ strict: true });
  return ajv.compile(schema);
}

const validate = compile(readSchema());

const KID = 'a'.repeat(64);
const PUBKEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const SNP = '7f'.repeat(48);
const SHA = 'ab'.repeat(32);

/** A document that pins everything, used as the base the cases below vary one field of. */
function full(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    issuers: ['ashaveri-prod'],
    instances: ['cvm-1'],
    keys: { [KID]: PUBKEY },
    measurements: { snp: [SNP] },
    maxReceiptAgeSeconds: 60,
    maxEvidenceAgeSeconds: 120,
    trustAnchors: { amdArks: [{ path: 'roots/ark.pem', sha256: SHA }] },
    ...overrides,
  };
}

function loaderAccepts(document: unknown): boolean {
  try {
    parsePolicyFile(JSON.stringify(document));
    return true;
  } catch (err) {
    if (err instanceof SdkError) return false;
    throw err;
  }
}

function schemaAccepts(document: unknown): boolean {
  return validate(document) === true;
}

describe('policy-v1 JSON Schema and the loader decide the same documents', () => {
  it('accepts every document the loader accepts', () => {
    const accepted: Array<[string, Record<string, unknown>]> = [
      ['everything pinned', full()],
      ['one pin', { v: 1, issuers: ['a'] }],
      ['keys only', { v: 1, keys: { [KID]: PUBKEY } }],
      ['measurements only', { v: 1, measurements: { software: ['11'.repeat(32)] } }],
      ['instances only', { v: 1, instances: ['i'] }],
      ['no trustAnchors field', full({ trustAnchors: undefined })],
      ['trustAnchors null', full({ trustAnchors: null })],
      ['a family null', full({ trustAnchors: { amdArks: null } })],
      ['every family null', full({ trustAnchors: { amdArks: null, intelSgxRoots: null, nvidiaRoots: null } })],
      ['a family pinned to nothing', full({ trustAnchors: { amdArks: [] } })],
      ['an age window written as null', full({ maxReceiptAgeSeconds: null })],
      ['every software kind', full({ measurements: { software: ['11'.repeat(32)] } })],
      ['every composite kind', full({ measurements: { 'tdx+gpucc': [SNP], 'snp+gpucc': [SNP] } })],
      ['a repeated value in a set', { v: 1, issuers: ['a', 'a'] }],
    ];
    for (const [label, document] of accepted) {
      expect(loaderAccepts(document), `${label}: loader`).toBe(true);
      expect(schemaAccepts(document), `${label}: schema`).toBe(true);
    }
  });

  it('refuses every document the loader refuses', () => {
    const refused: Array<[string, unknown]> = [
      ['a missing version', { issuers: ['a'] }],
      ['an unknown version', full({ v: 2 })],
      ['a version that is a string', full({ v: '1' })],
      ['no pin at all', { v: 1 }],
      ['an unknown key', full({ issuer: 'a' })],
      ['an unknown anchor family', full({ trustAnchors: { amdArk: [] } })],
      ['an unknown anchor field', full({ trustAnchors: { amdArks: [{ path: 'a.pem', sha256: SHA, digest: SHA }] } })],
      ['issuers as a string', full({ issuers: 'a' })],
      ['issuers empty', full({ issuers: [] })],
      ['issuers null', full({ issuers: null })],
      ['an issuer that is empty', full({ issuers: [''] })],
      ['an issuer with a tab in it', full({ issuers: ['a\tb'] })],
      ['an issuer with a line separator in it', full({ issuers: [String.fromCodePoint(0x2028)] })],
      ['instances as an object', full({ instances: { a: 'b' } })],
      ['keys empty', full({ keys: {} })],
      ['a kid that is not hex', full({ keys: { zz: PUBKEY } })],
      ['a kid in the wrong case', full({ keys: { [KID.toUpperCase()]: PUBKEY } })],
      ['a key with padding', full({ keys: { [KID]: `${PUBKEY}=` } })],
      ['a key of the wrong width', full({ keys: { [KID]: PUBKEY.slice(1) } })],
      ['measurements as an array', full({ measurements: [SNP] })],
      ['measurements empty', full({ measurements: {} })],
      ['an unknown environment kind', full({ measurements: { sgx: [SNP] } })],
      ['a measurement list that is empty', full({ measurements: { snp: [] } })],
      ['a software measurement at a TEE width', full({ measurements: { software: [SNP] } })],
      ['a TEE measurement at a software width', full({ measurements: { snp: ['11'.repeat(32)] } })],
      ['a measurement in upper case', full({ measurements: { snp: [SNP.toUpperCase()] } })],
      ['an age window as a string', full({ maxReceiptAgeSeconds: '60' })],
      ['an age window of zero', full({ maxReceiptAgeSeconds: 0 })],
      ['an age window that is not whole', full({ maxReceiptAgeSeconds: 1.5 })],
      ['trustAnchors as an array', full({ trustAnchors: [] })],
      ['an anchor family as a string', full({ trustAnchors: { amdArks: 'ark.pem' } })],
      ['an anchor entry that is a number', full({ trustAnchors: { amdArks: [4] } })],
      ['an anchor with no digest', full({ trustAnchors: { amdArks: [{ path: 'ark.pem' }] } })],
      ['an anchor with no path', full({ trustAnchors: { amdArks: [{ sha256: SHA }] } })],
      ['an anchor digest that is not 64 hex', full({ trustAnchors: { amdArks: [{ path: 'ark.pem', sha256: 'ab' }] } })],
      ['an absolute anchor path', full({ trustAnchors: { amdArks: [{ path: '/etc/ark.pem', sha256: SHA }] } })],
      ['a drive-letter anchor path', full({ trustAnchors: { amdArks: [{ path: 'C:/ark.pem', sha256: SHA }] } })],
      ['an empty anchor path', full({ trustAnchors: { amdArks: [{ path: '', sha256: SHA }] } })],
    ];
    for (const [label, document] of refused) {
      expect(loaderAccepts(document), `${label}: loader`).toBe(false);
      expect(schemaAccepts(document), `${label}: schema`).toBe(false);
    }
  });

  it('holds the loader to a stricter reading of four things a schema cannot say', () => {
    // Each of these is a document the schema waves through and the loader refuses, and each is a
    // silent-drop hazard rather than a shape the contract could carry:
    const loaderOnly: Array<[label: string, inMessage: string, document: string]> = [
      [
        'a repeated key',
        "repeats the key 'issuers'",
        '{"v":1,"issuers":["a"],"issuers":["b"]}',
      ],
      [
        'a base64url key whose last character is not canonical for its bytes',
        'canonical base64url',
        JSON.stringify(full({ keys: { [KID]: `${PUBKEY.slice(0, 42)}B` } })),
      ],
      [
        'an anchor path that climbs out of the directory',
        'climb out',
        JSON.stringify(full({ trustAnchors: { amdArks: [{ path: '../shared/ark.pem', sha256: SHA }] } })),
      ],
      [
        'an age window past the point an integer stops being exact',
        'whole number',
        JSON.stringify(full({ maxReceiptAgeSeconds: Number.MAX_SAFE_INTEGER + 2 })),
      ],
    ];
    for (const [label, inMessage, text] of loaderOnly) {
      const shape = JSON.parse(text) as unknown;
      expect(schemaAccepts(shape), `${label}: schema`).toBe(true);
      let message = '';
      try {
        parsePolicyFile(text);
      } catch (err) {
        message = err instanceof SdkError ? err.message : String(err);
      }
      expect(message, label).not.toBe('');
      expect(message, label).toContain(inMessage);
    }
  });

  it('describes the invisible-character class the loader actually runs', () => {
    const schema = readSchema() as { $defs: { pinnedText: { pattern: string } } };
    expect(schema.$defs.pinnedText.pattern).toBe(PINNED_TEXT_PATTERN);
  });

  it('refuses to compile a keyword this schema does not define', () => {
    // The same text with `strict: false` compiles and silently drops the keyword, so this is the
    // case that shows strict mode is on rather than a decoration.
    const misspelled = readSchema() as { $defs: { hex32: Record<string, unknown> } };
    misspelled.$defs.hex32.patterntypo = misspelled.$defs.hex32.pattern;
    delete misspelled.$defs.hex32.pattern;
    expect(() => compile(misspelled)).toThrow(/unknown keyword/);
    expect(() => compile(readSchema())).not.toThrow();
  });
});

describe('the policy digest as a published value', () => {
  it('is the string the vectors say, for the document they name', () => {
    // Pinned literally: a change to the canonical form, the domain string or the field set is a
    // change to every digest anyone has ever cited, so it has to be a decision rather than an edit.
    const vectors: Array<[Record<string, unknown>, string]> = [
      [
        { v: 1, issuers: ['ashaveri-mock'] },
        'sha256:3329595b14993b16992a6577f332a05b34821e33454a53a24575a1c9902c91d6',
      ],
      [
        {
          v: 1,
          issuers: ['ashaveri-prod'],
          instances: ['cvm-1'],
          keys: { [KID]: PUBKEY },
          measurements: { snp: [SNP] },
          maxReceiptAgeSeconds: 60,
          maxEvidenceAgeSeconds: null,
          trustAnchors: {
            amdArks: [{ path: 'roots/ark.pem', sha256: SHA }],
            intelSgxRoots: null,
            nvidiaRoots: [{ path: 'roots/device-ca.pem', sha256: 'cd'.repeat(32) }],
          },
        },
        'sha256:008742152d91f71b57ca1c63ddf29220d9b7b396cc77954e28575114a43cd373',
      ],
    ];
    for (const [document, digest] of vectors) {
      expect(policyFileDigest(parsePolicyFile(JSON.stringify(document)))).toBe(digest);
    }
  });
});
