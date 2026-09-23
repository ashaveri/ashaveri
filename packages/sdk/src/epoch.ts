import type { DeploymentManifest } from './manifest.js';
import type { SdkErrorCode } from './errors.js';

/**
 * What a receipt claims about the key that signed it, and the manifest's answer.
 *
 * A receipt carries its epoch (`epk`) inside the signature and its `kid` inside the protected header,
 * so the two are the signer's own statement about which key and which moment produced it. The
 * manifest is the deployment's statement about which keys it held in which epochs. This file asks
 * whether those two statements are the same story, which is the question a verifier could not ask at
 * all before the epoch members of `keys[]` existed: any declared key was accepted for any epoch, and
 * a reader had no way to tell a retired key from one that was never valid.
 *
 * Three shapes of answer, and the rule is one function so the client and the offline reporter cannot
 * drift apart:
 *
 * - A manifest that declares windows: the receipt's epoch must be one of them, the key must be one
 *   this epoch's entry names, and the receipt's own stamp must fall inside the window that entry
 *   opens. The bound is what makes retention safe. Without it a retained key could sign today's
 *   traffic and have the result read as a record from before the rotation.
 * - A manifest that declares none, which is every manifest published before epochs meant anything:
 *   the only epoch such a document states is its current `epk`, and the only keys it attributes to it
 *   are the ones it lists. That is a weaker reading, and it is the honest one: the manifest says
 *   nothing about a past epoch, so a receipt naming one is not supported by anything here rather than
 *   refused as a forgery.
 * - Either way the answer is a verdict with a reason attached, because a report that only said "the
 *   epoch is fine" would be the same silence this replaces.
 */

/** The claim a receipt makes about its own signing key. */
export interface ReceiptEpochClaim {
  /** The protected header's `kid`, as 64 lowercase hex characters. */
  readonly kid: string;
  /** The payload's `epk`. */
  readonly epoch: number;
  /** The payload's `iat`, unix seconds, which is what a window is measured against. */
  readonly issuedAt: number;
}

/** The epoch a receipt was adjudicated against, and the window that admitted it. */
export interface EpochAccepted {
  readonly ok: true;
  /**
   * Whether the admission came from a declared window (`windows`) or from the single current epoch a
   * manifest without windows states (`current-epoch`). The two are different strengths of evidence
   * and a report should not blur them.
   */
  readonly basis: 'windows' | 'current-epoch';
  readonly epoch: number;
  readonly kid: string;
  /**
   * The window that admitted this receipt. Both bounds are null on the `current-epoch` basis, which
   * is a manifest that states which keys it holds and no moment at all about when: an invented zero
   * here would read as a deployment that had published a start and chosen the epoch.
   */
  readonly validFrom: number | null;
  readonly validTo: number | null;
  /** True when the deployment's current epoch has moved past this one and the key is still retained. */
  readonly superseded: boolean;
  readonly detail: string;
}

/** Why a receipt's epoch claim is not the story this manifest tells. */
export interface EpochRefused {
  readonly ok: false;
  /**
   * `MANIFEST_EPOCH_UNDECLARED` when no entry of this manifest names the epoch at all, and
   * `MANIFEST_EPOCH_DISAGREES` when the epoch is declared and this receipt does not fit it, either
   * because a different key holds it or because the stamp is outside its window. A pin failure is a
   * third answer, `MANIFEST_KEY_NOT_PINNED`, and keeping the three apart is the point: the first says
   * the deployment never claimed this epoch, the second says its claim and this signature disagree,
   * and the third says only that this client has not designated the key.
   */
  readonly code: Extract<SdkErrorCode, 'MANIFEST_EPOCH_UNDECLARED' | 'MANIFEST_EPOCH_DISAGREES'>;
  readonly epoch: number;
  readonly kid: string;
  readonly detail: string;
}

export type EpochVerdict = EpochAccepted | EpochRefused;

/**
 * Adjudicate one receipt's epoch claim against one deployment manifest.
 *
 * This function throws nothing and decides nothing about keys: it is the rule, and the two places that
 * need it, `GatewaySession.resolveKey` on the live path and the offline reporter in the CLI, call it
 * and act on the answer. A second copy of the rule is the failure this product exists to prevent, so
 * there is one.
 */
export function adjudicateReceiptEpoch(
  manifest: DeploymentManifest,
  claim: ReceiptEpochClaim,
): EpochVerdict {
  if (manifest.epochs === null) return adjudicateCurrentEpochOnly(manifest, claim);
  const declared = manifest.epochs.find((entry) => entry.epoch === claim.epoch);
  if (declared === undefined) {
    return {
      ok: false,
      code: 'MANIFEST_EPOCH_UNDECLARED',
      epoch: claim.epoch,
      kid: claim.kid,
      detail: `epoch ${claim.epoch} is declared by no entry of this manifest, which publishes ${manifest.epochs
        .map((entry) => entry.epoch)
        .join(', ')}`,
    };
  }
  if (!declared.kids.includes(claim.kid)) {
    return {
      ok: false,
      code: 'MANIFEST_EPOCH_DISAGREES',
      epoch: claim.epoch,
      kid: claim.kid,
      detail: `epoch ${claim.epoch} is declared under ${declared.kids.join(' or ')}, not under the key this receipt was signed with`,
    };
  }
  if (claim.issuedAt < declared.validFrom || (declared.validTo !== null && claim.issuedAt >= declared.validTo)) {
    return {
      ok: false,
      code: 'MANIFEST_EPOCH_DISAGREES',
      epoch: claim.epoch,
      kid: claim.kid,
      detail: `this receipt is stamped ${claim.issuedAt}, outside the epoch ${claim.epoch} window of ${declared.validFrom} to ${declared.validTo ?? 'no published end'}`,
    };
  }
  return {
    ok: true,
    basis: 'windows',
    epoch: declared.epoch,
    kid: claim.kid,
    validFrom: declared.validFrom,
    validTo: declared.validTo,
    superseded: declared.epoch < manifest.epk,
    detail:
      declared.epoch < manifest.epk
        ? `epoch ${declared.epoch} was superseded by ${manifest.epk} and the deployment still retains its key`
        : `epoch ${declared.epoch} is this deployment's current epoch`,
  };
}

/**
 * The one epoch such a manifest states, and every key it lists.
 *
 * Refusing a receipt that names any other epoch is not a tightening invented here: the manifest holds
 * no claim about such an epoch, so a verifier that accepted one was trusting a value nobody vouched
 * for. This is the reading `epk` has had in the format from the beginning, which is
 * `Signing-key epoch, for key rotation` in section 3 of the specification, and it is what the member
 * means when nothing richer is published beside it.
 */
function adjudicateCurrentEpochOnly(
  manifest: DeploymentManifest,
  claim: ReceiptEpochClaim,
): EpochVerdict {
  if (claim.epoch !== manifest.epk) {
    return {
      ok: false,
      code: 'MANIFEST_EPOCH_UNDECLARED',
      epoch: claim.epoch,
      kid: claim.kid,
      detail: `this manifest declares one epoch, ${manifest.epk}, and names no window for ${claim.epoch}: a deployment that rotates a key publishes a new process at a higher epoch, so a receipt from another epoch is not answered by this document`,
    };
  }
  if (!manifest.keys.some((key) => key.kid === claim.kid)) {
    return {
      ok: false,
      code: 'MANIFEST_EPOCH_DISAGREES',
      epoch: claim.epoch,
      kid: claim.kid,
      detail: `epoch ${claim.epoch} belongs to the keys this manifest lists, and this receipt's key is not among them`,
    };
  }
  return {
    ok: true,
    basis: 'current-epoch',
    epoch: manifest.epk,
    kid: claim.kid,
    validFrom: 0,
    validTo: null,
    superseded: false,
    detail: `epoch ${claim.epoch} is the only epoch this manifest declares, and the key is one of the keys it lists`,
  };
}
