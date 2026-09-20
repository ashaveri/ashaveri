import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { MEASUREMENT_BYTES } from '@ashaveri/receipt';
import {
  SdkError,
  fromBase64Url,
  loadPolicyFromText,
  parsePolicyFile,
  policyFileDigest,
  policyFileFromPolicy,
  policyFileToJson,
  toBase64Url,
  toHex,
  type AshaveriPolicy,
  type PolicyFile,
  type SdkErrorCode,
} from '../src/index.js';

const TEMP = mkdtempSync(join(tmpdir(), 'ashaveri-policy-'));
afterAll(() => {
  rmSync(TEMP, { recursive: true, force: true });
});

const KID = 'a'.repeat(64);
const OTHER_KID = 'b'.repeat(64);
/** base64url of 32 zero bytes, the width an Ed25519 public key has. */
const PUBKEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
/** base64url of 32 one-bytes, computed so this file cannot miscount the width it means. */
const OTHER_PUBKEY = toBase64Url(new Uint8Array(32).fill(1));
/** One more encoding of the same 32 bytes as PUBKEY: the last character holds two unused bits. */
const NON_CANONICAL_PUBKEY = `${PUBKEY.slice(0, 42)}B`;
const SNP_MEASUREMENT = '7f'.repeat(48);
const SOFTWARE_MEASUREMENT = '11'.repeat(32);
const ANCHOR_BYTES = new TextEncoder().encode('-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n');
const ANCHOR_DIGEST = toHex(sha256(ANCHOR_BYTES));

/** The smallest document that names a pin; used where only one field matters. */
function minimal(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { v: 1, issuers: ['ashaveri-prod'], ...extra };
}

function anchor(path: string, digest = ANCHOR_DIGEST): Record<string, unknown> {
  return { path, sha256: digest };
}

function refusal(document: unknown): SdkErrorCode {
  try {
    parsePolicyFile(typeof document === 'string' ? document : JSON.stringify(document));
  } catch (err) {
    expect(err, `a refusal is an SdkError, got ${String(err)}`).toBeInstanceOf(SdkError);
    return (err as SdkError).code;
  }
  throw new Error('expected a refusal, but the document was accepted');
}

function refuseWith(document: unknown, code: SdkErrorCode): string {
  try {
    parsePolicyFile(typeof document === 'string' ? document : JSON.stringify(document));
  } catch (err) {
    expect(err).toBeInstanceOf(SdkError);
    expect((err as SdkError).code).toBe(code);
    return (err as SdkError).message;
  }
  throw new Error(`expected ${code}, but the document was accepted`);
}

function codeOf(build: () => unknown): SdkErrorCode {
  try {
    build();
  } catch (err) {
    expect(err).toBeInstanceOf(SdkError);
    return (err as SdkError).code;
  }
  throw new Error('expected a refusal, but the value was accepted');
}

function parse(document: Record<string, unknown>): PolicyFile {
  return parsePolicyFile(JSON.stringify(document));
}

/** A directory holding `ark.pem`, which the anchor paths in these documents resolve against. */
function anchorDir(name: string, bytes: Uint8Array = ANCHOR_BYTES): string {
  const dir = join(TEMP, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'ark.pem'), bytes);
  return dir;
}

describe('parsePolicyFile', () => {
  it('reads a full document into the policy object it names', async () => {
    const dir = anchorDir('full');
    const loaded = await loadPolicyFromText(
      JSON.stringify({
        v: 1,
        issuers: ['ashaveri-prod'],
        instances: ['cvm-1', 'cvm-2'],
        keys: { [KID]: PUBKEY },
        measurements: { snp: [SNP_MEASUREMENT], software: [SOFTWARE_MEASUREMENT] },
        maxReceiptAgeSeconds: 60,
        maxEvidenceAgeSeconds: 120,
        trustAnchors: { amdArks: [anchor('ark.pem')] },
      }),
      dir,
    );
    const policy: AshaveriPolicy = loaded.policy;
    expect(policy.issuers).toEqual(['ashaveri-prod']);
    expect(policy.instances).toEqual(['cvm-1', 'cvm-2']);
    expect(policy.keys).toEqual({ [KID]: PUBKEY });
    expect(policy.measurements).toEqual({ snp: [SNP_MEASUREMENT], software: [SOFTWARE_MEASUREMENT] });
    expect(policy.maxReceiptAgeSeconds).toBe(60);
    expect(policy.maxEvidenceAgeSeconds).toBe(120);
    expect(policy.trustAnchors?.amdArks).toEqual([ANCHOR_BYTES]);
    expect(policy.trustAnchors?.intelSgxRoots).toBeUndefined();
    expect(loaded.anchors).toEqual([{ family: 'amdArks', path: 'ark.pem', sha256: ANCHOR_DIGEST }]);
    expect(fromBase64Url(PUBKEY)).toHaveLength(32);
  });

  it('refuses a key this format does not define, and names both keys', () => {
    const message = refuseWith(minimal({ issuer: 'ashaveri-prod' }), 'POLICY_FILE_INVALID');
    expect(message).toContain("unknown key 'issuer'");
    expect(message).toContain('issuers');
  });

  it('refuses an unknown key nested inside an object it does define', () => {
    expect(
      refusal(minimal({ trustAnchors: { amdArks: [anchor('ark.pem', 'ab'.repeat(32))], amdArk: [] } })),
    ).toBe('POLICY_FILE_INVALID');
    const family = refuseWith(
      minimal({ trustAnchors: { amdArk: [anchor('ark.pem', 'ab'.repeat(32))] } }),
      'POLICY_FILE_INVALID',
    );
    expect(family).toContain('trustAnchors');
    expect(family).toContain("unknown key 'amdArk'");
    const entry = refuseWith(
      minimal({ trustAnchors: { amdArks: [{ ...anchor('ark.pem', 'ab'.repeat(32)), digest: 'ab' }] } }),
      'POLICY_FILE_INVALID',
    );
    expect(entry).toContain('trustAnchors.amdArks[0]');
    expect(entry).toContain("unknown key 'digest'");
  });

  it('refuses a missing v, and a v that is not the one number', () => {
    expect(refusal({ issuers: ['x'] })).toBe('POLICY_FILE_INVALID');
    expect(refusal(minimal({ v: 2 }))).toBe('POLICY_FILE_INVALID');
    expect(refusal(minimal({ v: '1' }))).toBe('POLICY_FILE_INVALID');
    expect(refusal(minimal({ v: null }))).toBe('POLICY_FILE_INVALID');
    expect(refuseWith(minimal({ v: 2 }), 'POLICY_FILE_INVALID')).toContain('v must be 1');
  });

  it('refuses a wrong type in every position the format pins', () => {
    const cases: Array<[string, unknown]> = [
      ['issuers', 'ashaveri-prod'],
      ['issuers', [1]],
      ['issuers', null],
      ['instances', { a: 'b' }],
      ['keys', [KID]],
      ['keys', { [KID]: 7 }],
      ['keys', { [KID]: null }],
      ['measurements', ['snp']],
      ['measurements', { snp: SNP_MEASUREMENT }],
      ['measurements', { snp: [42] }],
      ['measurements', { snp: null }],
      ['maxReceiptAgeSeconds', '60'],
      ['maxReceiptAgeSeconds', 1.5],
      ['maxReceiptAgeSeconds', 0],
      ['maxReceiptAgeSeconds', -1],
      ['maxReceiptAgeSeconds', Number.MAX_SAFE_INTEGER + 1],
      ['maxEvidenceAgeSeconds', true],
      ['trustAnchors', []],
      ['trustAnchors', 0],
      ['trustAnchors', { amdArks: 'ark.pem' }],
      ['trustAnchors', { amdArks: [{ path: 'ark.pem' }] }],
      ['trustAnchors', { amdArks: [{ path: 'ark.pem', sha256: 'zz' }] }],
      ['trustAnchors', { amdArks: [4] }],
      ['trustAnchors', { amdArks: [{ path: 4, sha256: 'ab'.repeat(32) }] }],
    ];
    for (const [field, value] of cases) {
      expect(refusal(minimal({ [field]: value })), `${field}=${JSON.stringify(value)}`).toBe('POLICY_FILE_INVALID');
    }
  });

  it('refuses an environment kind it does not know', () => {
    expect(refuseWith(minimal({ measurements: { sgx: [SNP_MEASUREMENT] } }), 'POLICY_FILE_INVALID')).toContain('sgx');
  });

  it('refuses a measurement whose width disagrees with its kind', () => {
    for (const [tee, bytes] of Object.entries(MEASUREMENT_BYTES)) {
      expect(parse(minimal({ measurements: { [tee]: ['ab'.repeat(bytes)] } })).measurements).toEqual({
        [tee]: ['ab'.repeat(bytes)],
      });
      const wrong = bytes === 32 ? 48 : 32;
      const message = refuseWith(minimal({ measurements: { [tee]: ['ab'.repeat(wrong)] } }), 'POLICY_FILE_INVALID');
      expect(message).toContain(`must be ${bytes * 2} hex characters`);
    }
  });

  it('refuses hex in a spelling the receipt format does not use', () => {
    const bad = ['AB'.repeat(48), `${SNP_MEASUREMENT.slice(0, 94)}zz`, `${SNP_MEASUREMENT}ab`, SNP_MEASUREMENT.slice(1)];
    for (const value of bad) {
      const message = refuseWith(minimal({ measurements: { snp: [value] } }), 'POLICY_FILE_INVALID');
      expect(message, value).toContain('hex');
    }
  });

  it('refuses a public key that is not base64url of exactly 32 bytes', () => {
    const bad = [`${PUBKEY}=`, `${PUBKEY}A`, PUBKEY.slice(1), PUBKEY.replace(/A/g, '+')];
    for (const value of bad) {
      expect(refusal(minimal({ keys: { [KID]: value } })), value).toBe('POLICY_FILE_INVALID');
    }
    // Two spellings of one key byte string is two operators believing they pinned the same key.
    expect(refuseWith(minimal({ keys: { [KID]: NON_CANONICAL_PUBKEY } }), 'POLICY_FILE_INVALID')).toContain(
      'base64url',
    );
  });

  it('refuses a kid that is not 64 lowercase hex', () => {
    const bad = ['A'.repeat(64), 'ab'.repeat(31), 'zz'.repeat(32)];
    for (const value of bad) {
      expect(refusal(minimal({ keys: { [value]: PUBKEY } })), value).toBe('POLICY_FILE_INVALID');
    }
  });

  it('refuses a pin carrying a character a reader cannot see', () => {
    // The characters are named by code point rather than written out: a test that refuses an unseen
    // character should not have to carry one, and one carried in a source file cannot be reviewed.
    const unseen = [0x09, 0x7f, 0xad, 0x202e, 0x2028, 0x200b, 0xfeff, 0x2060];
    for (const code of unseen) {
      const pin = `cvm-${String.fromCodePoint(code)}1`;
      expect(refusal(minimal({ issuers: [pin] })), `U+${code.toString(16).toUpperCase()}`).toBe('POLICY_FILE_INVALID');
    }
    expect(refusal(minimal({ issuers: [''] }))).toBe('POLICY_FILE_INVALID');
    expect(refusal(minimal({ keys: { [KID]: PUBKEY, '': PUBKEY } }))).toBe('POLICY_FILE_INVALID');
    expect(refusal(minimal({ measurements: { snp: [' 7f'.padEnd(96, '7')] } }))).toBe('POLICY_FILE_INVALID');
  });

  it('refuses a document that repeats one key, because the first value would be dropped', () => {
    const message = refuseWith('{"v":1,"issuers":["a"],"issuers":["b"]}', 'POLICY_FILE_INVALID');
    expect(message).toContain("repeats the key 'issuers'");
    // The duplicate has to be caught at any depth, including inside the pinned key map.
    expect(refusal(`{"v":1,"issuers":["a"],"keys":{"${KID}":"${PUBKEY}","${KID}":"${PUBKEY}"}}`)).toBe(
      'POLICY_FILE_INVALID',
    );
    expect(refusal('{"v":1,"issuers":["a"],"issuers":["a"]}')).toBe('POLICY_FILE_INVALID');
    expect(refusal('{"v":1,"issuers":["a"],"v":1}')).toBe('POLICY_FILE_INVALID');
  });

  it('refuses text that is not exactly one JSON document', () => {
    const bad = [
      'not json',
      '',
      '[]',
      '"a string"',
      'null',
      '{"v":1,"issuers":["a"],}',
      '{} {}',
      '{"v":1,"issuers":["a"]}\u0000',
      '{"v":1,"issuers":[0x1]}',
      "{'v':1}",
    ];
    for (const document of bad) {
      expect(refusal(document), JSON.stringify(document)).toBe('POLICY_FILE_INVALID');
    }
  });

  it('refuses a policy that pins nothing, and names what is missing', () => {
    const message = refuseWith({ v: 1 }, 'POLICY_NOTHING_PINNED');
    expect(message).toContain('issuers');
    expect(message).toContain('measurements');
    // A vendor root is not a pin against a receipt, so it cannot turn an empty policy into a policy.
    expect(refusal({ v: 1, trustAnchors: { amdArks: [anchor('ark.pem', 'ab'.repeat(32))] } })).toBe(
      'POLICY_NOTHING_PINNED',
    );
  });

  it('refuses an empty pin collection and names which one', () => {
    for (const field of ['issuers', 'instances', 'keys', 'measurements']) {
      const empty: unknown = field === 'keys' || field === 'measurements' ? {} : [];
      const message = refuseWith({ v: 1, issuers: ['a'], [field]: empty }, 'POLICY_EMPTY_PIN');
      expect(message, field).toContain(`'${field}'`);
    }
    // An empty list under a known kind is the same accident.
    expect(refuseWith(minimal({ measurements: { snp: [] } }), 'POLICY_EMPTY_PIN')).toContain('measurements.snp');
  });

  it('refuses an anchor path that is absolute, empty, or leaves the directory holding the policy', () => {
    const bad = ['/etc/ssl/ark.pem', 'C:/windows/ark.pem', '../shared/ark.pem', '../../etc/passwd', '.', 'sub/../..', ''];
    for (const path of bad) {
      const message = refuseWith(
        minimal({ trustAnchors: { amdArks: [anchor(path, 'ab'.repeat(32))] } }),
        'POLICY_FILE_INVALID',
      );
      expect(message, path).toContain('path');
    }
    expect(refusal(minimal({ trustAnchors: { amdArks: [anchor('a\u0000.pem', 'ab'.repeat(32))] } }))).toBe(
      'POLICY_FILE_INVALID',
    );
  });

  it('reads a backslash path as the same anchor the forward-slash spelling names', () => {
    const backslash = parse(
      minimal({ trustAnchors: { nvidiaRoots: [anchor('roots\\device-ca.pem', 'ab'.repeat(32))] } }),
    );
    const forward = parse(
      minimal({ trustAnchors: { nvidiaRoots: [anchor('roots/device-ca.pem', 'ab'.repeat(32))] } }),
    );
    expect(backslash).toEqual(forward);
    expect(policyFileDigest(backslash)).toBe(policyFileDigest(forward));
  });
});

describe('policyFileDigest', () => {
  const NVIDIA = [anchor('roots/device-ca.pem', 'cd'.repeat(32))];
  const AMD = [anchor('roots/ark.pem', 'ab'.repeat(32))];
  /** The anchor block `full()` carries, with the AMD family swapped for one case at a time. */
  function anchorsWith(amdArks: unknown): Record<string, unknown> {
    return { nvidiaRoots: NVIDIA, amdArks };
  }

  /** A document with pins in every position, so a field left out of the digest would show up. */
  function full(): Record<string, unknown> {
    return {
      v: 1,
      issuers: ['ashaveri-prod', 'ashaveri-staging'],
      instances: ['cvm-2', 'cvm-1'],
      keys: { [OTHER_KID]: PUBKEY, [KID]: PUBKEY },
      measurements: { tdx: [SNP_MEASUREMENT], snp: [SNP_MEASUREMENT] },
      maxReceiptAgeSeconds: 60,
      maxEvidenceAgeSeconds: 120,
      trustAnchors: anchorsWith(AMD),
    };
  }

  function digestOf(document: Record<string, unknown>): string {
    return policyFileDigest(parse(document));
  }

  it('is one prefixed hex digest', () => {
    expect(digestOf(full())).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('does not move when the file is reformatted', () => {
    const digest = digestOf(full());
    // Key order in the document and in each pinned map.
    const reordered: Record<string, unknown> = {
      maxEvidenceAgeSeconds: 120,
      maxReceiptAgeSeconds: 60,
      trustAnchors: full().trustAnchors,
      measurements: { snp: [SNP_MEASUREMENT], tdx: [SNP_MEASUREMENT] },
      keys: { [KID]: PUBKEY, [OTHER_KID]: PUBKEY },
      instances: ['cvm-2', 'cvm-1'],
      issuers: ['ashaveri-prod', 'ashaveri-staging'],
      v: 1,
    };
    expect(digestOf(reordered)).toBe(digest);
    // Whitespace between the tokens, which is what a formatter or a pretty-printer changes.
    expect(policyFileDigest(parsePolicyFile(policyFileToJson(parse(full()))))).toBe(digest);
    expect(policyFileDigest(parsePolicyFile(JSON.stringify(parse(full()))))).toBe(digest);
    expect(policyFileDigest(parsePolicyFile(JSON.stringify(parse(full()), null, 6)))).toBe(digest);
    // The line endings of the file itself, which a checkout may rewrite, are outside the digest
    // because the digest is taken over the loaded policy.
    const pretty = policyFileToJson(parse(full()));
    expect(policyFileDigest(parsePolicyFile(pretty.replace(/\n/gu, '\r\n')))).toBe(digest);
    // A set given in the other order, and one given twice.
    expect(digestOf({ ...full(), issuers: ['ashaveri-staging', 'ashaveri-prod'] })).toBe(digest);
    expect(digestOf({ ...full(), issuers: ['ashaveri-prod', 'ashaveri-staging', 'ashaveri-prod'] })).toBe(digest);
    expect(digestOf({ ...full(), keys: { [KID]: PUBKEY, [OTHER_KID]: PUBKEY } })).toBe(digest);
    // An omitted field and the default it stands for hash the same, which is why the digest is taken
    // over the loaded policy rather than over the bytes of the file.
    expect(digestOf({ v: 1, issuers: ['a'], maxReceiptAgeSeconds: null })).toBe(digestOf({ v: 1, issuers: ['a'] }));
    expect(digestOf({ v: 1, issuers: ['a'], trustAnchors: null })).toBe(digestOf({ v: 1, issuers: ['a'] }));
    expect(
      digestOf({ v: 1, issuers: ['a'], trustAnchors: { amdArks: null, intelSgxRoots: null, nvidiaRoots: null } }),
    ).toBe(digestOf({ v: 1, issuers: ['a'] }));
    // One assertion in the other direction, so the equality above cannot be satisfied by a digest
    // that ignores the document it was handed.
    expect(digestOf({ ...full(), trustAnchors: { amdArks: [anchor('roots/ark.pem', 'ab'.repeat(32))] } })).not.toBe(
      digest,
    );
  });

  it('moves when a pin moves', () => {
    const base = digestOf(full());
    const changes: Array<[string, Record<string, unknown>]> = [
      ['issuer', { ...full(), issuers: ['ashaveri-evil', 'ashaveri-staging'] }],
      ['instance', { ...full(), instances: ['cvm-2', 'cvm-3'] }],
      ['pinned key', { ...full(), keys: { [OTHER_KID]: OTHER_PUBKEY, [KID]: PUBKEY } }],
      ['kid', { ...full(), keys: { [OTHER_KID]: PUBKEY, ['c'.repeat(64)]: PUBKEY } }],
      [
        'measurement',
        { ...full(), measurements: { tdx: [SNP_MEASUREMENT], snp: [`8${SNP_MEASUREMENT.slice(1)}`] } },
      ],
      ['a dropped measurement kind', { ...full(), measurements: { snp: [SNP_MEASUREMENT] } }],
      ['receipt age', { ...full(), maxReceiptAgeSeconds: 61 }],
      ['evidence age', { ...full(), maxEvidenceAgeSeconds: null }],
      [
        'anchor path',
        { ...full(), trustAnchors: anchorsWith([anchor('roots/other-ark.pem', 'ab'.repeat(32))]) },
      ],
      ['anchor digest', { ...full(), trustAnchors: anchorsWith([anchor('roots/ark.pem', 'ae'.repeat(32))]) }],
      [
        'a second anchor',
        {
          ...full(),
          trustAnchors: anchorsWith([
            anchor('roots/ark.pem', 'ab'.repeat(32)),
            anchor('roots/ark2.pem', 'ac'.repeat(32)),
          ]),
        },
      ],
      ['an anchor family pinned to nothing', { ...full(), trustAnchors: anchorsWith([]) }],
      ['a pin dropped altogether', { v: 1, issuers: ['ashaveri-prod', 'ashaveri-staging'] }],
    ];
    for (const [label, document] of changes) {
      expect(digestOf(document), label).not.toBe(base);
    }
  });

  it('separates an unpinned vendor root from a pinned one and from trust-nothing', () => {
    const unpinned = digestOf({ v: 1, issuers: ['a'] });
    const pinned = digestOf({ v: 1, issuers: ['a'], trustAnchors: { amdArks: [anchor('ark.pem', 'ab'.repeat(32))] } });
    const trustsNothing = digestOf({ v: 1, issuers: ['a'], trustAnchors: { amdArks: [] } });
    expect(new Set([unpinned, pinned, trustsNothing]).size).toBe(3);
  });

  it('gives one digest to a document whose pin lists differ only in order', () => {
    expect(digestOf({ v: 1, measurements: { snp: [SNP_MEASUREMENT] }, issuers: ['b', 'a', 'a'] })).toBe(
      digestOf({ v: 1, issuers: ['a', 'b'], measurements: { snp: [SNP_MEASUREMENT] } }),
    );
  });
});

describe('policyFileFromPolicy', () => {
  it('writes the file form of an object and reads back the same digest', () => {
    const policy: AshaveriPolicy = {
      issuers: ['b', 'a'],
      instances: ['i'],
      keys: { [KID]: PUBKEY },
      measurements: { snp: [SNP_MEASUREMENT] },
      maxEvidenceAgeSeconds: 30,
    };
    const file = policyFileFromPolicy(policy);
    expect(policyFileDigest(file)).toBe(policyFileDigest(parsePolicyFile(policyFileToJson(file))));
    expect(file.issuers).toEqual(['a', 'b']);
    expect(file.maxReceiptAgeSeconds).toBeNull();
    expect(file.trustAnchors).toEqual({ amdArks: null, intelSgxRoots: null, nvidiaRoots: null });
    expect(parsePolicyFile(policyFileToJson(file))).toEqual(file);
  });

  it('carries the anchor bytes the object pins as their path and digest', () => {
    const file = policyFileFromPolicy(
      { issuers: ['a'], trustAnchors: { amdArks: [ANCHOR_BYTES], nvidiaRoots: [ANCHOR_BYTES] } },
      { amdArks: ['roots/ark.pem'], nvidiaRoots: ['roots/device-ca.pem'] },
    );
    expect(file.trustAnchors?.amdArks).toEqual([anchor('roots/ark.pem', ANCHOR_DIGEST)]);
    expect(file.trustAnchors?.nvidiaRoots).toEqual([anchor('roots/device-ca.pem', ANCHOR_DIGEST)]);
    expect(file.trustAnchors?.intelSgxRoots).toBeNull();
    expect(() =>
      policyFileFromPolicy({ issuers: ['a'], trustAnchors: { amdArks: [ANCHOR_BYTES, ANCHOR_BYTES] } }, {
        amdArks: ['one.pem'],
      }),
    ).toThrow(/path/);
    // No path for a family the object pins is a refusal, not an anchor silently left out of the file.
    expect(() => policyFileFromPolicy({ issuers: ['a'], trustAnchors: { amdArks: [ANCHOR_BYTES] } })).toThrow(/path/);
  });

  it('refuses an object that pins nothing, on the same rule the file form is held to', () => {
    expect(codeOf(() => policyFileFromPolicy({}))).toBe('POLICY_NOTHING_PINNED');
  });
});

describe('loadPolicyFromText', () => {
  it('refuses an anchor whose bytes are not what the file recorded', async () => {
    const dir = anchorDir('drifted', new TextEncoder().encode('a different certificate'));
    const err = await loadPolicyFromText(JSON.stringify(minimal({ trustAnchors: { amdArks: [anchor('ark.pem')] } })), dir).catch(
      (cause: unknown) => cause,
    );
    expect(err).toBeInstanceOf(SdkError);
    expect((err as SdkError).code).toBe('POLICY_ANCHOR_DIGEST_MISMATCH');
    expect((err as SdkError).message).toContain('ark.pem');
    expect((err as SdkError).message).toContain(ANCHOR_DIGEST);
  });

  it('refuses an anchor whose line endings a checkout rewrote, by name', async () => {
    const crlf = new TextDecoder().decode(ANCHOR_BYTES).replaceAll('\n', '\r\n');
    const dir = anchorDir('crlf', new TextEncoder().encode(crlf));
    const err = await loadPolicyFromText(JSON.stringify(minimal({ trustAnchors: { amdArks: [anchor('ark.pem')] } })), dir).catch(
      (cause: unknown) => cause,
    );
    expect((err as SdkError).code).toBe('POLICY_ANCHOR_DIGEST_MISMATCH');
  });

  it('refuses an anchor it cannot read, naming the path and its position', async () => {
    const dir = anchorDir('missing');
    const err = await loadPolicyFromText(
      JSON.stringify(minimal({ trustAnchors: { nvidiaRoots: [anchor('absent.pem')] } })),
      dir,
    ).catch((cause: unknown) => cause);
    expect(err).toBeInstanceOf(SdkError);
    expect((err as SdkError).code).toBe('POLICY_ANCHOR_UNREADABLE');
    expect((err as SdkError).message).toContain('absent.pem');
    expect((err as SdkError).message).toContain('nvidiaRoots[0]');
  });

  it('keeps an empty anchor family empty, so it still means trust nothing', async () => {
    const dir = anchorDir('trust-nothing');
    const loaded = await loadPolicyFromText(JSON.stringify(minimal({ trustAnchors: { amdArks: [] } })), dir);
    expect(loaded.policy.trustAnchors).toEqual({ amdArks: [] });
    expect(loaded.policy.trustAnchors?.intelSgxRoots).toBeUndefined();
  });

  it('omits trustAnchors entirely when the policy pins no vendor root', async () => {
    const dir = anchorDir('no-anchors');
    const loaded = await loadPolicyFromText(JSON.stringify(minimal()), dir);
    expect(loaded.policy.trustAnchors).toBeUndefined();
    expect(loaded.anchors).toEqual([]);
  });

  it('resolves an anchor below a nested directory named with either separator', async () => {
    const base = anchorDir('nested');
    mkdirSync(join(base, 'roots'), { recursive: true });
    writeFileSync(join(base, 'roots', 'device-ca.pem'), ANCHOR_BYTES);
    for (const spelling of ['roots/device-ca.pem', 'roots\\device-ca.pem']) {
      const loaded = await loadPolicyFromText(
        JSON.stringify(minimal({ trustAnchors: { nvidiaRoots: [anchor(spelling)] } })),
        base,
      );
      expect(loaded.policy.trustAnchors?.nvidiaRoots, spelling).toEqual([ANCHOR_BYTES]);
    }
  });

  it('reports the digest of the policy it loaded, not of the bytes it read', async () => {
    const dir = anchorDir('digest');
    const document = JSON.stringify({ v: 1, issuers: ['a'], keys: { [KID]: PUBKEY } });
    const loaded = await loadPolicyFromText(document, dir);
    expect(loaded.digest).toBe(policyFileDigest(parsePolicyFile(document)));
    expect(loaded.file).toEqual(parsePolicyFile(document));
  });
});
