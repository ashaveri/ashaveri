import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The inputs the single-file verifier is proved against, written into a directory that holds nothing else.
 *
 * The CI job that runs the bundle needs a policy and a deployment manifest whose pins match the committed
 * receipt it is about to check, and this started life as a script pasted into the workflow file. That shape
 * is the reason it is a file now: a heredoc inside a job is read by no `tsconfig`, so a wrong field name in
 * it fails on a runner, in a pull request, with nothing local able to reach it first. As a script it is
 * typechecked with the rest of this package and runnable by hand, which is the only way the bundle's proof
 * can be observed anywhere other than Actions.
 *
 * Nothing is invented here. Every value is read out of the committed vector, so the generated document
 * cannot state a pin the receipt does not carry, and the verification time is the vector's own `iat`
 * rather than the wall clock, because this is not re-issuing a receipt.
 */

/** The committed signing key material a fixture receipt was issued under. */
interface FixtureKey {
  readonly kid: string;
  readonly publicKey: string;
}

/** The JSON rendering of the published valid receipt, whose payload the pins are read from. */
interface FixtureReceipt {
  readonly payload: {
    readonly iss: string;
    readonly ins: string;
    readonly mdl: string;
    readonly wts: string;
    readonly epk: number;
    readonly nce: string;
    readonly req: string;
    readonly res: string;
    readonly iat: number;
    readonly meas: { readonly tee: string; readonly m: string };
  };
}

/** Hex key bytes to the unpadded base64url spelling the manifest and the policy both use. */
function publicKeyFromHex(hex: string): string {
  if (!/^[0-9a-f]+$/u.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`the fixture key is not lowercase hex of whole bytes: ${hex}`);
  }
  return Buffer.from(hex, 'hex').toString('base64url');
}

function main(): void {
  const [workDir, dataDir] = process.argv.slice(2);
  if (workDir === undefined || dataDir === undefined) {
    throw new Error('usage: offline-proof <work-directory> <fixtures-data-directory>');
  }

  const key = JSON.parse(readFileSync(join(dataDir, 'keys/receipt-key-v1.json'), 'utf8')) as FixtureKey;
  const { payload } = JSON.parse(
    readFileSync(join(dataDir, 'receipts/receipt-valid-v1.json'), 'utf8'),
  ) as FixtureReceipt;
  const publicKey = publicKeyFromHex(key.publicKey);

  writeFileSync(
    join(workDir, 'manifest.json'),
    JSON.stringify({
      v: 1,
      iss: payload.iss,
      ins: payload.ins,
      epk: payload.epk,
      keys: [{ kid: key.kid, alg: 'Ed25519', publicKey }],
      models: [{ id: payload.mdl, wts: payload.wts }],
      meas: { tee: payload.meas.tee, m: payload.meas.m },
    }),
  );

  writeFileSync(
    join(workDir, 'policy.json'),
    JSON.stringify({
      v: 1,
      issuers: [payload.iss],
      instances: [payload.ins],
      keys: { [key.kid]: publicKey },
      measurements: { [payload.meas.tee]: [payload.meas.m] },
      maxReceiptAgeSeconds: 300,
      maxEvidenceAgeSeconds: 900,
    }),
  );

  // Sourced by the job so the verifier is handed the four values it needs. A receipt is checked against
  // the time it names, so a step that used the current clock would fail a valid vector.
  writeFileSync(
    join(workDir, 'args.env'),
    `NONCE=${payload.nce}\nREQ=${payload.req}\nRES=${payload.res}\nNOW=${new Date(payload.iat * 1000).toISOString()}\n`,
  );

  process.stdout.write(`wrote manifest.json, policy.json and args.env into ${workDir}\n`);
}

main();
