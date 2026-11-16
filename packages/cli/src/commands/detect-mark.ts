import {
  DISCLOSURE_RECORD_LIMITS,
  ReceiptError,
  equalBytes,
  extractMarkedRegion,
  fromBase64Url,
  toHex,
} from '@ashaveri/receipt';
import { SdkError, hashRequest, verifyReceipt } from '@ashaveri/sdk';
import { escapeInvisible, UsageError, writeJson } from '../usage.js';
import { KEY_FLAG, designatedKeys, readBytes, type DesignatedKey } from './verify-receipt.js';

/**
 * `ashaveri detect-mark <receipt> --response-body <file> --key <b64url>...`: what the mark can and
 * cannot prove about a receipt and the response bytes beside it.
 *
 * The detection is the published extraction rule, `extractMarkedRegion` in `@ashaveri/receipt`, run
 * over the bytes the caller holds: the same rule the gateway writes from and the live client checks
 * with, so a third party's detector and the client's verdict are about one span of bytes. The checks
 * run in the client's own order, the one `verifyMarkedRegion` in `@ashaveri/sdk` states: the signature
 * and payload first through `verifyReceipt`, then the response digest against `res`, so a region taken
 * from a document the receipt does not attest cannot become a verdict, then the region's digest against
 * `mk.d`. The codes are the ones those checks already answer with, and this command adds none.
 *
 * What the answer owes a reader is both halves. A mark standing alone in a transcript is a string
 * anyone can type; what makes one this deployment's is the digest inside a signed payload whose `res`
 * covers the bytes around it, so the report says what the pair establishes and never what the member
 * alone establishes. And the limits are a product requirement of this output rather than a comment:
 * every run prints, in both renderings, the format's own limits sentence, the one a disclosure record
 * carries verbatim, so a reader holding only text is told what the mark cannot prove in the same
 * spelling wherever they meet it.
 *
 * The command reads no policy, compares no nonce against a challenge and consults no clock: those are
 * the questions `ashaveri verify-receipt` answers, and the report names them as open rather than
 * letting a detection verdict read as a verification one.
 */

/** The flags `detect-mark` reads, typed as the one parse in `cli.ts` produces them. */
export interface DetectMarkFlags {
  key?: string[];
  'response-body'?: string;
  json?: boolean;
}

/** One key this run accepts a signature from, resolved by the kid the receipt's own header names. */
function resolveEvidence(keys: readonly DesignatedKey[]): (kid: Uint8Array) => Uint8Array | undefined {
  return (kid) => {
    const found = keys.find((each) => each.kid === toHex(kid));
    return found === undefined ? undefined : fromBase64Url(found.publicKey);
  };
}

/** The refusal this command owes in the same shape the handover verbs give: the code, and the message. */
function refuse(err: ReceiptError | SdkError, json: boolean): number {
  if (json) {
    writeJson({ ok: false, code: err.code, message: err.message });
  } else {
    process.stderr.write(`verification failed (${err.code}): ${escapeInvisible(err.message)}\n`);
  }
  return 1;
}

export async function runDetectMark(positionals: readonly string[], values: DetectMarkFlags): Promise<number> {
  const json = values.json === true;
  const receiptPath = positionals[0];
  if (receiptPath === undefined) {
    throw new UsageError('detect-mark needs a receipt file, or - for stdin');
  }
  if (positionals.length > 1) {
    throw new UsageError(`detect-mark reads one receipt, and '${positionals[1]}' is a second argument it has no reading for`);
  }
  const responsePath = values['response-body'];
  if (responsePath === undefined) {
    throw new UsageError(
      '--response-body is required: every receipt this format states names a marking, whose claim is a digest of one region read out of exactly these bytes, and a digest of bytes nobody handed over is not a check',
    );
  }
  const keys = designatedKeys(values.key, KEY_FLAG);
  if (keys.length === 0) {
    throw new UsageError(`${KEY_FLAG} is required: a mark standing alone is a string anyone can type, and the signature is what makes it this deployment's`);
  }

  const receiptBytes = await readBytes(receiptPath, 'receipt');
  const responseBytes = await readBytes(responsePath, 'response body');

  let verified;
  try {
    verified = verifyReceipt(receiptBytes, { resolveKey: resolveEvidence(keys) });
  } catch (err) {
    if (err instanceof ReceiptError || err instanceof SdkError) return refuse(err, json);
    throw err;
  }
  const payload = verified.payload;
  const kid = toHex(verified.header.kid);

  try {
    // The client's order: the whole response first, so a region out of bytes the receipt does not
    // attest cannot become a verdict, then the region its own scheme names, then the region's digest.
    if (!equalBytes(hashRequest(responseBytes), payload.res)) {
      throw new SdkError(
        'RESPONSE_HASH_MISMATCH',
        `the response bytes handed for the marking check do not hash to the digest the receipt attests (${toHex(payload.res)})`,
      );
    }
    const region = extractMarkedRegion(payload.mk.sch, responseBytes);
    if (!equalBytes(hashRequest(region), payload.mk.d)) {
      throw new ReceiptError(
        'MARK_MISMATCH',
        `the ${payload.mk.sch} region of these bytes hashes to ${toHex(hashRequest(region))}, not to the ${toHex(payload.mk.d)} the receipt carries`,
      );
    }
    const regionDigest = toHex(hashRequest(region));
    const proves =
      payload.mk.sch === 'none'
        ? 'the response bytes are the ones the receipt attests and carry no region of the shape provenance-v1 names, which is the absence the signed none declaration claims'
        : 'the response bytes are the ones the receipt attests, they carry exactly one region of the shape provenance-v1 names, and that region hashes to the digest the signed payload carries; the marking member states the accompanying content was generated';
    const notChecked =
      "the nonce against a challenge, the request digest against any bytes, the pins a policy names and the age windows a clock closes: 'ashaveri verify-receipt' decides those, from the receipt, a policy file and a deployment manifest";
    if (json) {
      writeJson({
        ok: true,
        scheme: payload.mk.sch,
        kid,
        signature: 'holds',
        responseDigest: 'match',
        region: {
          count: payload.mk.sch === 'none' ? 0 : 1,
          byteLength: region.length,
          sha256: regionDigest,
          digestMatch: true,
        },
        proves,
        cannotProve: DISCLOSURE_RECORD_LIMITS,
        notChecked: [notChecked],
      });
    } else {
      const lines = [
        `marking scheme: ${payload.mk.sch}`,
        `signature: holds under the designated key ${kid}`,
        `response digest: matches res (${toHex(payload.res)})`,
        payload.mk.sch === 'none'
          ? `marked region: no region of this response is marked, and the receipt attests that absence (the empty region, ${regionDigest})`
          : `marked region: one region, ${String(region.length)} bytes, sha256 matches mk.d (${regionDigest})`,
        `what the mark proves: ${proves}`,
        `what the mark cannot prove: ${DISCLOSURE_RECORD_LIMITS}`,
        `not checked: ${notChecked}`,
      ];
      process.stdout.write(`${lines.map((line) => escapeInvisible(line)).join('\n')}\n`);
    }
    return 0;
  } catch (err) {
    if (err instanceof ReceiptError || err instanceof SdkError) return refuse(err, json);
    throw err;
  }
}