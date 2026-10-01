import { ed25519 } from '@noble/curves/ed25519';
import { sha256, sha384 } from '@noble/hashes/sha2.js';
import { labeled } from './seed.ts';
import { emptyRegion, hashRequest, type ReceiptPayload, type SigningKey } from '@ashaveri/receipt';

/**
 * The receipt document every published vector that needs one is built from, held beside the fixtures
 * generator that wrote it first.
 *
 * Three suites sign a receipt over a claim of their own: the marked-region suite attests a response and
 * the region inside it, and the two digest suites attest a body they then hand a reader in a shape that
 * does not hash to it. Each of those needs a real `COSE_Sign1` rather than a description of one, because
 * the refusal a vector states is the one a client answers with after checking a signature, and an
 * unsigned stand-in would refuse for the wrong reason. This file is the one place the field set and the
 * signing key are spelled, so a suite cannot drift to a key the published `data/keys/` file does not
 * name or to a payload no fixture is issued under.
 */

/** The instant every published receipt fixture is issued at, so regenerating changes no byte. */
export const FIXED_IAT = 1_772_000_000;

/**
 * The response body the original four fixtures attest. Every row the receipt suite began with carries
 * `res` as the digest of these bytes, and the command that verifies a receipt now owes its reader the
 * marked region as well as the digest, so the bytes are published beside the row rather than left as a
 * value a reader can only reach by guessing the preimage. They are synthetic on purpose: a completion
 * body whose content is a label is a fixture, and this corpus publishes no real traffic.
 */
export const FIXTURE_RESPONSE = new TextEncoder().encode('ashaveri-fixtures/response/v1');

/** The fixture signing key, derived from its seed the way `generate.ts` derives the committed one. */
export function fixtureKey(): SigningKey {
  const privateKey = labeled('ashaveri-fixtures/receipt-key/v1');
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey, kid: sha256(publicKey) };
}

/**
 * The document every published receipt vector starts from, at the one version the format declares. `v` is
 * pinned in the literal below and an override cannot move a published fixture into a format its bytes
 * never claimed. The twelve shared fields come first, then the four a receipt states about itself, each
 * holding the shortest truthful answer an issuance that took nothing in and served one buffered body gives:
 * a declared absence rather than a silence. A suite whose bytes say something else overrides the member at
 * its own call site, beside the bytes that make the answer true.
 */
export function fixturePayload(overrides: Partial<ReceiptPayload> = {}): ReceiptPayload {
  const res = hashRequest(FIXTURE_RESPONSE);
  const base: ReceiptPayload = {
    v: 1,
    iss: 'dpl-9f2a41c3',
    ins: 'cvm-i-047f2a',
    iat: FIXED_IAT,
    nce: labeled('ashaveri-fixtures/nonce/v1', 16),
    req: labeled('ashaveri-fixtures/request/v1'),
    res,
    mdl: 'meta-llama/Llama-3.1-8B-Instruct',
    wts: labeled('ashaveri-fixtures/manifest/v1'),
    meas: { tee: 'snp+gpucc', m: sha384(new TextEncoder().encode('ashaveri-fixtures/measurement/v1')) },
    att: {
      d: labeled('ashaveri-fixtures/evidence/v1'),
      ts: FIXED_IAT - 60,
      url: 'https://inference.ashaveri.com/v1/attestation',
    },
    epk: 1,
    tok: { p: 128, c: 64 },
    mk: { sch: 'none', d: sha256(emptyRegion()) },
    sd: { name: 'host clock', uncertaintySeconds: null },
    cva: {
      collateral: { presence: 'not-taken-in', reason: 'this corpus takes no collateral in' },
      validity: { presence: 'not-taken-in', reason: 'this corpus records no validity context' },
    },
    // The buffered body is one item and it is the whole of `res`, and no item is dated at or after the
    // document attesting it, so the default is the instant before `iat`.
    itm: [{ t: FIXED_IAT - 1, d: res }],
  };
  const merged = { ...base, ...overrides };
  // A row that moves `res` moves the one item with it. Two suites sign over the same buffered response,
  // and an override that left `itm[0].d` on the digest the defaults carried would state two answers about
  // one body and make the two files disagree for a reason neither of them wrote on purpose.
  return overrides.res !== undefined && overrides.itm === undefined
    ? { ...merged, itm: [{ t: merged.itm[0]!.t, d: overrides.res }] }
    : merged;
}
