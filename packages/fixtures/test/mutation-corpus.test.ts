import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The corpora the hostile-input properties in the two parser packages mutate. They are pinned by
 * digest on purpose: a generator built over a corpus that quietly became empty, or stopped
 * containing the structure the properties claim to break, keeps passing while asserting nothing.
 * A digest that moves means someone changed what the properties read, which is a decision worth
 * making out loud rather than a line that scrolls past in a green run.
 *
 * The paths reach into the other package's committed test fixtures, which is a read of shared
 * bytes and not an import of its code: nothing here depends on how a property file finds a corpus,
 * so a broken generator in either package cannot make this agree with itself.
 */
const SNP_REPORT_SIZE = 0x4a0;

/** Where the SNP report sits inside the captured envelope. */
const REPORT_OFFSET = 4;

const CORPORA: ReadonlyArray<{ readonly path: string; readonly bytes: number; readonly sha384: string }> = [
  {
    path: '../../attest-core/test/fixtures/sev-snp-attestation.bin',
    bytes: 4045,
    sha384: '403e434fc7a7bedcd18b762f0c0662614b30816b1c3a9ac5b27f2413f42b823be5f08acd80b50283fc60bb6762cf211b',
  },
  {
    path: '../../attest-core/test/fixtures/tdx-quote-v4.bin',
    bytes: 4936,
    sha384: 'bb07a2c849dded6c591959b7ff6f350d48397a93acf093bf692bef51924d220baf7f728e1a4b82cc7e943845862aed78',
  },
  {
    path: '../../attest-core/test/fixtures/nvidia-hopper-report.bin',
    bytes: 4052,
    sha384: '74bfbbfcc87d2a5e7fede253a83945142bbe7dd197153a6dc943173c37a72977969c353d2b3b3d2647cf23fff59506c0',
  },
  {
    path: '../../attest-core/test/fixtures/nvidia-hopper-cert-chain.pem',
    bytes: 4826,
    sha384: '7cae87b0d4f2a1e59b6cd08a8a089ae9f6d24433b350f4646f50b2c9c1a26e1be1ac493c7cc3d66b0b5d05e760ed83b2',
  },
];

const sha384 = (bytes: Uint8Array): string => createHash('sha384').update(bytes).digest('hex');
const read = (path: string): Uint8Array => new Uint8Array(readFileSync(fileURLToPath(new URL(path, import.meta.url))));

describe('the corpora that hostile input is built from', () => {
  for (const corpus of CORPORA) {
    it(`${corpus.path.split('/').at(-1)} is present, unchanged and large enough to mutate`, () => {
      const bytes = read(corpus.path);
      // The length is pinned to the byte, so "large enough to truncate" is settled by the number
      // above rather than by a floor that would have to be right for four different formats.
      expect(bytes.length).toBe(corpus.bytes);
      expect(sha384(bytes)).toBe(corpus.sha384);
    });
  }

  it('the envelope still carries the report the SNP properties mutate, at the pinned place', () => {
    const envelope = read(CORPORA[0]!.path);
    const report = envelope.slice(REPORT_OFFSET, REPORT_OFFSET + SNP_REPORT_SIZE);
    expect(report.length).toBe(SNP_REPORT_SIZE);
    expect(sha384(report)).toBe('2a2b50ee749b475f5923c5a7904223ddff9f75a66eb8a96bd91b97b86282b6ad37a07351bd667527ac91704d13abd1f7');
    // Two fields the report layout puts at fixed places, so the pinned window is a report and not
    // just pinned bytes: version 2 or 3, and the signature algorithm this package reads.
    expect([2, 3]).toContain(new DataView(report.buffer, report.byteOffset).getUint32(0x00, true));
    expect(new DataView(report.buffer, report.byteOffset).getUint32(0x34, true)).toBe(1);
    // Once and only once: a second window with the same digest would mean the carve below could
    // have landed anywhere, and the offset pinned above would be a coincidence.
    const text = Buffer.from(envelope).toString('latin1');
    const window = Buffer.from(report).toString('latin1');
    expect(text.indexOf(window, REPORT_OFFSET + 1)).toBe(-1);
    expect(envelope.length).toBeGreaterThan(SNP_REPORT_SIZE + REPORT_OFFSET);
  });

  it('the bundle the GPU properties mutate is still the two fixtures assembled the way nvattest writes them', () => {
    const report = read(CORPORA[2]!.path);
    const chain = read(CORPORA[3]!.path);
    const bundle = new TextEncoder().encode(
      JSON.stringify([
        {
          arch: 'hopper',
          evidence: Buffer.from(report).toString('base64'),
          certificate: Buffer.from(chain).toString('base64'),
          version: '1.1.0',
        },
      ]),
    );
    expect(bundle.length).toBe(11908);
    expect(sha384(bundle)).toBe('5024feb5426b5c0ca146047ba38c879af0c6624aa5008237f0c7e3af937c4fba3c54ef67335559e5794d8adb3e3e2b42');
    // That the two payloads sit inside as text is the assembly above, not an assertion below it:
    // base64's alphabet carries no quote and no backslash, so `JSON.stringify` cannot change either
    // string, and a containment check here agrees with its own construction whatever the fixtures
    // hold. The digest is what makes the assembly the one the properties mutate.
  });
});
