import { adjudicateReceiptEpoch } from './epoch.js';
import { SdkError } from './errors.js';
import type { DeploymentManifest } from './manifest.js';
import type { AshaveriPolicy } from './policy.js';
import { assertClockMillis } from './verify.js';

/**
 * What the key route's boot-scoped binding document claims about itself, the three facts a reader
 * weighs its freshness against.
 *
 * The key route serves the session public half beside a platform attestation whose report data is
 * `sha256(pk)`, the key identifier the receipt header states. That attestation is collected once at
 * boot and is constant for the whole boot, so the document is replayable standing evidence: a client
 * choosing whether to seal a prompt holds it at handshake, before any receipt exists. These are the
 * facts such a document states about its own moment and key, named for the binding rather than for a
 * receipt, and shaped like `ReceiptEpochClaim` so the rotation rule reads them without a second copy.
 *
 * `issuedAt` is the attestation's instant, unix seconds, the moment the platform quote behind the
 * binding was collected. It is what an age is measured from, and it is what the epoch window admits.
 */
export interface KeyBindingClaim {
  /** The deployment signing key the binding is boot-scoped under, as 64 lowercase hex characters. */
  readonly kid: string;
  /** The epoch (`epk`) whose key carries this session key. */
  readonly epoch: number;
  /** The attestation instant, unix seconds, which the age and the epoch window are measured against. */
  readonly issuedAt: number;
}

/**
 * Refuse a key binding older than the policy demands, with the epoch that carries its key as the
 * ceiling the demand cannot exceed.
 *
 * The demand is `maxKeyBindingAgeSeconds`, and a policy naming none demands nothing: the function
 * returns and a document of any date is accepted. That absence is the weakness owned in the open at
 * the field's declaration, the same posture a reader takes toward collateral it is not asked to
 * appraise, and it is why no verdict taken under a policy written before this field existed moves.
 * `Number.POSITIVE_INFINITY` is the deliberate off switch, the same spelling the receipt and evidence
 * windows use.
 *
 * When a finite demand is named, two bounds close on the document. The first is the epoch: the binding
 * must belong to an epoch the manifest supports and its instant must fall inside that epoch's window,
 * which `adjudicateReceiptEpoch` decides, which is the one place the rotation rule lives. The second is
 * the age, and the epoch is its ceiling: a binding is never good beyond the epoch that carries its key,
 * so the demanded age is capped at the span from the binding's instant to the end of that epoch's
 * window. A demand larger than that span admits nothing past the epoch's end, and a manifest that
 * publishes no window states no end, so the demand stands alone. A document older than the bound that
 * remains is refused `KEY_BINDING_TOO_OLD`.
 *
 * The clock is asked the same question `verifyCompletionReceipt` asks, through the same guard, before
 * either bound weighs anything: a reading that is not a whole number of milliseconds in this estate's
 * span is the caller's argument to fix, not a verdict about the binding.
 */
export function assertKeyBindingFreshUnderPolicy(
  policy: AshaveriPolicy | undefined,
  claim: KeyBindingClaim,
  manifest: DeploymentManifest,
  nowMillis?: number,
): void {
  const demanded = policy?.maxKeyBindingAgeSeconds;
  if (demanded === undefined || demanded === Number.POSITIVE_INFINITY) return;
  if (nowMillis !== undefined) assertClockMillis(nowMillis);
  const nowSeconds = Math.floor((nowMillis ?? Date.now()) / 1000);

  const verdict = adjudicateReceiptEpoch(manifest, claim);
  if (!verdict.ok) {
    throw new SdkError(
      verdict.code,
      `the key binding for ${claim.kid} claims epoch ${claim.epoch} attested at ${claim.issuedAt}, and the deployment manifest does not support it: ${verdict.detail}`,
    );
  }

  // The epoch is the ceiling the demand cannot exceed: a binding is never good beyond the window of
  // the epoch that carries its key, so a demand wider than the span left in that window is held down
  // to it. A manifest that publishes no window states no end, and the demand stands as written.
  const bound =
    verdict.basis === 'windows' && verdict.validTo !== null
      ? Math.min(demanded, verdict.validTo - claim.issuedAt)
      : demanded;
  const age = nowSeconds - claim.issuedAt;
  if (age > bound) {
    const ceiling =
      verdict.basis === 'windows' && verdict.validTo !== null && bound < demanded
        ? `, itself capped by the epoch ${claim.epoch} window that ends at ${verdict.validTo}`
        : '';
    throw new SdkError(
      'KEY_BINDING_TOO_OLD',
      `the key binding for ${claim.kid} is refused: its attestation was collected at ${claim.issuedAt}, ${age} seconds before this reading, which is older than the ${demanded} seconds this policy demands a key binding be fresh at${ceiling}. Either the deployment serves a binding collected within the bound, or the policy raises the demand to a span this boot can answer`,
    );
  }
}