import { ed25519 } from '@noble/curves/ed25519';
import { sha256, sha384 } from '@noble/hashes/sha2.js';
import { labeled } from './seed.ts';
import type { ReceiptPayloadV1, SigningKey } from '@ashaveri/receipt';

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

/** The fixture signing key, derived from its seed the way `generate.ts` derives the committed one. */
export function fixtureKey(): SigningKey {
  const privateKey = labeled('ashaveri-fixtures/receipt-key/v1');
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey, kid: sha256(publicKey) };
}

/**
 * The v1 field set every published receipt starts from, so the helper names that version rather than
 * the union. `v` is pinned in the literal below and an override cannot move a published fixture into a
 * format its bytes never claimed: the v2 vectors state `v: 2` at their own call sites, beside the `mk`
 * that makes them v2, and never reach for it through here.
 */
export function fixturePayload(overrides: Partial<ReceiptPayloadV1> = {}): ReceiptPayloadV1 {
  return {
    v: 1,
    iss: 'dpl-9f2a41c3',
    ins: 'cvm-i-047f2a',
    iat: FIXED_IAT,
    nce: labeled('ashaveri-fixtures/nonce/v1', 16),
    req: labeled('ashaveri-fixtures/request/v1'),
    res: labeled('ashaveri-fixtures/response/v1'),
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
    ...overrides,
  };
}
