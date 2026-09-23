import { toHex } from './b64.js';
import { fromBase64Url } from './b64.js';
import type { EvidenceTrustAnchors } from './evidence.js';
import type { DeploymentManifest } from './manifest.js';

/**
 * How far the client's own clock may sit from a receipt's `iat` before strict mode refuses it:
 * how long after the gateway stamped a receipt a client may still be shown it.
 *
 * Five minutes is the published allowance for presenting a signed statement, taken from the two
 * ecosystems that print the number rather than leaving each implementer to invent one. MIT's
 * `krb5.conf` describes `[libdefaults] clockskew` as what "the library will tolerate before
 * assuming that a Kerberos message is invalid", and states "The default value is 300 seconds, or
 * five minutes"
 * (https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html). AWS, on the page
 * that owns Signature Version 4, gives the same horizon for how stale a signed request may be:
 * "In most cases, a request must reach AWS within five minutes of the time stamp in the request.
 * Otherwise, AWS denies the request"
 * (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html, "Why requests are signed").
 *
 * ashaveri sits at that line rather than below it for one reason specific to this check: neither
 * of those two systems is timing its own document. A KDC and an AWS endpoint both compare a
 * timestamp against a clock on hardware they administer, while `iat` was stamped by a gateway in a
 * confidential VM and is measured here against the clock of a laptop that VM does not own and
 * cannot keep in step. The window has to absorb the skew between two uncoordinated machines plus
 * the fetch of the receipt, which is what those protocols decided a roughly-set clock deserves.
 * Going wider is the wrong trade: past this much time a receipt is a perfectly valid record of a
 * conversation that finished, and a caller that accepts it is answering "is this a replay?" with a
 * signature.
 *
 * A policy with no `maxReceiptAgeSeconds` gets this number. A policy that says
 * `Number.POSITIVE_INFINITY` gets no receipt window at all, which is the archive case.
 */
export const DEFAULT_MAX_RECEIPT_AGE_SECONDS = 300;

/**
 * How far the client's clock may sit from a receipt's `att.ts`, the moment the platform quote it
 * commits to was collected. A different quantity from the one above, and deliberately looser.
 *
 * The looseness is not generosity about the clock; it is the shape of a completion. The gateway
 * starts the evidence fetch beside the upstream call and stamps `iat` after the last byte reaches
 * the client (`gateway/src/server.ts`: "Evidence is gathered while the model generates"), so the
 * quote is older than the receipt by the request's own duration and a verifier sees
 * `now - att.ts = (now - iat) + generation time`. Reusing the 300-second figure here would refuse
 * every long completion for a fault that is not the evidence's, so this is that figure plus ten
 * minutes of generation. The parts the gateway itself bounds sit well inside the addition: the
 * guest agent has 30 seconds per quote call and quotes serially on the TDX driver
 * (`gateway/src/guest.ts`), the first byte from an upstream may take two minutes
 * (`FIRST_EVENT_TIMEOUT_MS`, `gateway/src/server.ts`), and a device collection "costs a real device
 * seconds" (`gateway/src/dstack.ts`).
 *
 * What keeps this in minutes instead of hours is where evidence comes from, and it turned out to
 * come from the tight place. A live deployment mints it per request: the challenge is
 * `sha256(nonce, requestHash)` for the request being served, and `dstackDeployment` caches by that
 * challenge, so the evidence behind a receipt is always a cache miss and a fresh call to the guest
 * agent. The cache exists so a *re-read* of one challenge keeps returning the same bytes — `att.d`
 * binds `sha256(document)`, so `att.url` has to stay fetchable to mean anything — and not so an old
 * quote can answer a new request. Had it cut the other way, with standing evidence reused across
 * requests, `att.ts` would name a boot and no window in minutes could be both honest and usable:
 * this number would then have had to be an uptime, and the check would have stopped catching
 * anything.
 *
 * 900 seconds is also the horizon this gateway already publishes for a signed moment.
 * `REPLAY_WINDOW_SECONDS` in `gateway/src/access.ts` is how long a presented authorization stays
 * remembered on the serving side, so a client that stops trusting an evidence timestamp at the same
 * minute is not the only party keeping that hourglass.
 *
 * One limit stated plainly: nothing here bounds how long a completion may stream, so past roughly
 * fifteen minutes of generation it is this window, not the receipt one, that refuses the response.
 * A deployment that streams longer has to widen this in its clients' policies, and can.
 */
export const DEFAULT_MAX_EVIDENCE_AGE_SECONDS = 900;

/**
 * Client-side pinning policy. `strict` verification requires one: it pins the
 * signing keys, measurements, issuers and instances the client is willing to
 * accept, so a compromised or repointed gateway cannot swap any of them.
 *
 * It is also where the two clocks are set, and both of them run unless this object says
 * otherwise: strict verification is the path that has a policy, so the defaults above are the
 * defaults for a caller who configures nothing.
 */
export interface AshaveriPolicy {
  readonly issuers?: readonly string[];
  readonly instances?: readonly string[];
  /** Ed25519 public keys by kid (hex). */
  readonly keys?: Readonly<Record<string, string>>;
  /**
   * The public keys, by kid (hex), this client designates to authenticate the deployment manifest
   * itself, held apart from `keys` on purpose.
   *
   * A manifest decides which keys sign receipts, so a key that is trusted for receipts cannot also be
   * the proof that the document naming them is the deployment's own: one compromised signing key would
   * rewrite the rotation history that was supposed to retire it. Separating the two maps is what makes
   * a wrapper verified under a receipt key a refusal rather than a pass, and it is why this field names
   * a role rather than a second spelling of the same set.
   *
   * Naming none of these is not a weaker posture, it is a different question: the client checks no
   * manifest signature and reports the manifest as unauthenticated, which is what a deployment that was
   * never handed a manifest key deserves. Naming at least one makes an unauthenticated manifest a
   * refusal, because a caller who designated a signing identity for this document and was handed
   * another one has been shown a deployment that is not the one it pinned.
   *
   * This field lives on the policy object and not in the policy file format, which refuses a document
   * naming it as an unknown key: see the note by `PIN_FIELDS` in `policy-file.ts` for why the digest
   * question is a decision to make in the open rather than a side effect of this field arriving.
   */
  readonly manifestKeys?: Readonly<Record<string, string>>;
  /** Allowed measurements (hex), keyed by environment kind. */
  readonly measurements?: Readonly<Record<string, readonly string[]>>;
  /**
   * The client's own bound on how far a receipt's `iat` may sit from its clock. A number here wins
   * over `DEFAULT_MAX_RECEIPT_AGE_SECONDS`, in both directions: 60 refuses more than the default,
   * 1200 refuses less.
   *
   * Omitting this and setting `Number.POSITIVE_INFINITY` are not the same decision, and only one
   * of them is a claim. An absent field means nobody thought about the clock, so the default
   * guards it. Infinity means "I have thought about this, and the clock must not vote": it is what
   * a caller verifying an archived receipt writes, deliberately, because the alternative is a
   * number that silently accepts the archive too.
   */
  readonly maxReceiptAgeSeconds?: number;
  /**
   * The client's own bound on how far a receipt's `att.ts` may sit from its clock, with the same
   * two readings as `maxReceiptAgeSeconds`: a number wins over `DEFAULT_MAX_EVIDENCE_AGE_SECONDS`,
   * and `Number.POSITIVE_INFINITY` is the deliberate off switch rather than the absence of one.
   */
  readonly maxEvidenceAgeSeconds?: number;
  /**
   * Vendor roots hardware evidence must chain to. Omit to accept the roots
   * bundled with `@ashaveri/attest-core`; set it to pin your own.
   */
  readonly trustAnchors?: EvidenceTrustAnchors;
}

/**
 * The pins a deployment publishes, read out of its manifest. What these are worth depends on whether
 * the manifest arrived sealed and authenticated, which is a fact about the transport rather than about
 * this function: a manifest verified under a key this client designated out of band is the deployment's
 * own statement, and one it could not verify is trust-on-first-use, because the document came from the
 * party being verified. Strict mode checks the receipt against the pins either way, so an unverified
 * manifest can fail a check and cannot open one.
 *
 * `manifestKeys` is deliberately absent from the result. The manifest names no key that signs itself,
 * and a builder that filled that field from the document it was handed would manufacture the one
 * circularity the field exists to close: the signer would be designated by the signed. Whatever reaches
 * that map has to arrive from somewhere the deployment does not control.
 *
 * Neither window is set here, and that is the point. The manifest comes from the party being
 * verified, so it is not where a freshness rule may be loosened: what a manifest-derived policy
 * checks the clock against is `DEFAULT_MAX_RECEIPT_AGE_SECONDS` and
 * `DEFAULT_MAX_EVIDENCE_AGE_SECONDS`, which are in this package's code and on no wire.
 */
export function policyFromManifest(manifest: DeploymentManifest): AshaveriPolicy {
  const keys: Record<string, string> = {};
  for (const key of manifest.keys) {
    keys[key.kid] = key.publicKey;
  }
  return {
    issuers: [manifest.iss],
    instances: [manifest.ins],
    keys,
    measurements: { [manifest.meas.tee]: [manifest.meas.m] },
  };
}

export function policyKeyByKid(policy: AshaveriPolicy, kid: Uint8Array): Uint8Array | undefined {
  const encoded = policy.keys?.[toHex(kid)];
  return encoded === undefined ? undefined : fromBase64Url(encoded);
}
