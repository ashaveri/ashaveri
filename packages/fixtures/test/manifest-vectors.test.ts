import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  DEPLOYMENT_MANIFEST_CONTENT_TYPE,
  ReceiptError,
  decodeSealedDeploymentManifest,
  isSealedDeploymentManifest,
  toHex,
  verifySealedDeploymentManifest,
} from '@ashaveri/receipt';
import { loadSealedManifestVectors } from '../src/index.js';
import { unionMembers } from './doc-contract.js';

/**
 * The published sealed-manifest suite, read back against the artifacts it names.
 *
 * `data/manifest-v1.json` states where its format lives, which registries its answers come from, and what
 * each of its two verdict columns means. Every one of those is a copy of a fact held elsewhere, so this
 * reads the originals rather than restating them: the CDDL and its JSON twin are opened to check they
 * still carry the content type the suite is about, and the two error unions are read out of the source
 * that declares them to check that no row answers with a word nothing defines.
 *
 * The envelope column is checked here because the envelope reader is reachable from this package, and the
 * client column is not, because the three-state reading of a manifest lives in `@ashaveri/sdk`, which this
 * package does not depend on. That half is driven through the shipped client path in
 * `packages/cli/test/vector-conformance.test.ts`, which replays every row of this file and the epoch claims
 * beside them. What is checked below is therefore the file's own consistency and the layer beneath the
 * client, and the two together are why a row cannot state one answer in one column and a different fact in
 * the other without a gate noticing.
 */

const file = loadSealedManifestVectors();
const RECEIPT_ERRORS = '../../../packages/receipt/src/errors.ts';
const SDK_ERRORS = '../../../packages/sdk/src/errors.ts';
const BASE_FIELDS = ['name', 'note', 'documentBase64Url', 'documentByteLength', 'read', 'verdict', 'seal'];

const bytes = (base64url: string): Uint8Array => new Uint8Array(Buffer.from(base64url, 'base64url'));

/** What the envelope reader answers for a row, under the published key its own header names. */
function envelopeAnswer(documentBase64Url: string): string {
  const documentBytes = bytes(documentBase64Url);
  if (!isSealedDeploymentManifest(documentBytes)) return 'not-sealed';
  try {
    const seal = decodeSealedDeploymentManifest(documentBytes);
    const published = file.layout.keyMaterial.find((one) => one.kidHex === toHex(seal.header.kid));
    if (published === undefined) return 'kid-outside-the-material-this-suite-publishes';
    verifySealedDeploymentManifest(documentBytes, bytes(published.publicKeyBase64Url));
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

const designatedIds = new Set(file.vectors.flatMap((one) => one.read.designates.map((pin) => pin.kid)));
const publishedIds = new Set(file.layout.keyMaterial.map((one) => one.kidHex));

describe('the sealed deployment manifest vectors', () => {
  it('are a suite the format and its twin both still describe', () => {
    expect(file.version).toBe(1);
    expect(file.description.length).toBeGreaterThan(0);
    expect(file.layout.contentType).toBe(DEPLOYMENT_MANIFEST_CONTENT_TYPE);
    expect(file.layout.headerLabels).toEqual({ alg: 1, typ: 3, kid: 4 });
    // The prose field names a file and the section of it this suite states, so the file part is what a
    // reader can go and find.
    const named = [file.layout.format, file.layout.twin, file.layout.prose.split(' ')[0] ?? ''];
    for (const path of named) {
      expect(existsSync(fileURLToPath(new URL(`../../../${path}`, import.meta.url))), `${path} is named by the suite and is not there`).toBe(
        true,
      );
    }
    // The content type is the one field that separates this container from the two beside it, so a suite
    // that named a CDDL no longer carrying it would be pointing a port at the wrong file.
    const cddl = readFileSync(fileURLToPath(new URL(`../../../${file.layout.format}`, import.meta.url)), 'utf8');
    expect(cddl).toContain(`"${DEPLOYMENT_MANIFEST_CONTENT_TYPE}"`);
    const twin = JSON.parse(readFileSync(fileURLToPath(new URL(`../../../${file.layout.twin}`, import.meta.url)), 'utf8')) as {
      properties?: { protectedHeader?: { properties?: { typ?: { const?: unknown } } } };
    };
    expect(twin.properties?.protectedHeader?.properties?.typ?.const).toBe(DEPLOYMENT_MANIFEST_CONTENT_TYPE);
  });

  it('answers the envelope column it publishes, read back through the format package', () => {
    const observed = file.vectors.map((one) => `${one.name}: ${envelopeAnswer(one.documentBase64Url)}`);
    expect(observed).toEqual(file.vectors.map((one) => `${one.name}: ${one.seal}`));
  });

  it('names a designated key and a header kid only from the material it publishes', () => {
    for (const one of file.vectors) {
      expect(bytes(one.documentBase64Url)).toHaveLength(one.documentByteLength);
      for (const pin of one.read.designates) {
        expect(publishedIds.has(pin.kid), `${one.name} designates ${pin.kid}, which the suite publishes no key for`).toBe(
          true,
        );
      }
    }
    // Every signing key of a sealed row is also material a reader can find, which is what lets a port
    // reproduce a seal rather than only check one.
    for (const one of file.vectors) {
      if (!isSealedDeploymentManifest(bytes(one.documentBase64Url))) continue;
      let answer: string;
      try {
        answer = toHex(decodeSealedDeploymentManifest(bytes(one.documentBase64Url)).header.kid);
      } catch (err) {
        if (!(err instanceof ReceiptError)) throw err;
        continue;
      }
      expect(publishedIds.has(answer), `${one.name} is sealed under a kid the suite does not publish`).toBe(true);
    }
    expect(designatedIds.size).toBeGreaterThan(0);
  });

  it('carries no field a row is not told about and no code no registry declares', () => {
    const allowed = new Set([...BASE_FIELDS, ...file.layout.verdictFields]);
    for (const one of file.vectors) {
      for (const field of Object.keys(one)) {
        expect(allowed.has(field), `${one.name} carries ${field}, which the suite describes no field of`).toBe(true);
      }
      if (one.authentication === undefined) continue;
      expect(Object.keys(one.authentication).sort()).toEqual([...file.layout.authenticationFields].sort());
    }
    const declared = new Set([
      ...unionMembers('ReceiptErrorCode', RECEIPT_ERRORS),
      ...unionMembers('SdkErrorCode', SDK_ERRORS),
    ]);
    for (const one of file.vectors) {
      if (one.verdict === 'verify-ok') continue;
      expect(declared.has(one.verdict), `${one.name} answers ${one.verdict}, which no registry declares`).toBe(true);
    }
    // And the file's own roster is exactly the set its rows answer with, so a verdict that left the suite
    // is caught from both ends of the same list.
    expect([...file.layout.codes].sort()).toEqual(
      [...new Set(file.vectors.map((one) => one.verdict))].sort(),
    );
  });

  it('separates the two columns where a seal holds and the client still refuses', () => {
    // The pair is the substance of the suite: a document that verifies under a key nobody designated, and
    // a pin that disagrees with the id beside it, are different deployments with different fixes, and both
    // leave the envelope intact.
    const designation = new Set(['MANIFEST_NOT_AUTHENTICATED', 'MANIFEST_KEY_NOT_PINNED']);
    const designationRefusals = file.vectors.filter((one) => one.seal === 'verify-ok' && designation.has(one.verdict));
    expect(designationRefusals.length).toBeGreaterThanOrEqual(2);
    const tampering = file.vectors.filter((one) => one.seal === 'INVALID_SIGNATURE');
    expect(tampering.length).toBeGreaterThanOrEqual(2);
    for (const one of tampering) {
      expect(one.verdict, `${one.name} is a seal failure the client reports as something else`).toBe(
        'MANIFEST_SIGNATURE_INVALID',
      );
    }
    const accepted = file.vectors.filter((one) => one.verdict === 'verify-ok');
    expect(accepted.length).toBeGreaterThanOrEqual(6);
    // Three states, and each of them is accepted rather than refused.
    expect(
      [...new Set(accepted.map((one) => `${String(one.authentication?.sealed)}/${String(one.authentication?.authenticated)}`))].sort(),
    ).toEqual(['false/false', 'true/false', 'true/true']);
  });

  it('keeps the rotation history and the open parser in the rows that turn on them', () => {
    const windows = file.vectors.find((one) => one.name === 'rotation-history-retaining-a-superseded-key');
    expect(windows).toBeDefined();
    const parsed = windows?.parsed as { epochs: { epoch: number; validTo: number | null }[] } | undefined;
    expect(parsed?.epochs.map((entry) => [entry.epoch, entry.validTo])).toEqual([
      [1, 1_772_000_000],
      [2, null],
    ]);
    // A window's end is the successor's start and the highest epoch has no published end, which is the
    // only way a retained key cannot sign fresh traffic and read as a record from before the rotation.
    expect(windows?.claims?.some((row) => row.ok === true && row.superseded === true)).toBe(true);
    expect(windows?.claims?.some((row) => row.code === 'MANIFEST_EPOCH_DISAGREES')).toBe(true);
    const open = file.vectors.find((one) => one.name === 'document-member-unknown-to-version-one');
    expect(open?.dropped?.length).toBeGreaterThan(0);
    expect(open?.verdict).toBe('verify-ok');
  });
});
