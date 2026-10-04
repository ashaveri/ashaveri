import { readFile } from 'node:fs/promises';
import { keyId, type CollateralValidityAnchor } from '@ashaveri/receipt';
import { appraiseCarriedCollateral, type CollateralOutcome } from '@ashaveri/collateral';
import {
  DEFAULT_MAX_EVIDENCE_AGE_SECONDS,
  DEFAULT_MAX_RECEIPT_AGE_SECONDS,
  decodeReceipt,
  fromBase64Url,
  GatewaySession,
  hashRequest,
  isSealedDeploymentManifest,
  ReceiptError,
  SdkError,
  toBase64Url,
  toHex,
  type AnchorSlotLabel,
  type AnchorSlotReading,
  type AshaveriPolicy,
  type EpochVerdict,
  type ManifestAuthentication,
  type VerifiedReceipt,
} from '@ashaveri/sdk';
import { escapeInvisible, printedToken, UsageError, writeJson } from '../usage.js';
import {
  carriedDesignations,
  COLLATERAL_ORIGIN_FLAG,
  COLLATERAL_PLATFORM_FLAG,
  INTEL_ROOT_FLAG,
  once,
  questionText,
  refusalOf,
  rootRule,
  slotValue,
  type CarriedDesignations,
  type CarriedQuestion,
} from './carried-collateral.js';
import { readPolicyFile } from './verify.js';

/**
 * `ashaveri verify-receipt <receipt> [options]`: a verdict about a receipt from files alone.
 *
 * Every rule that decides what a receipt means lives in `@ashaveri/sdk`, beside the client that
 * enforces it while a deployment is answering: `verifyCompletionReceipt` for the payload against the
 * policy, and `GatewaySession.resolveKey` for the signing key against the policy and the deployment
 * manifest together. A second copy of those rules in this file would be the failure this product
 * exists to prevent, because two copies drift and only one of them is the one an auditor is told
 * about. So this command calls them.
 *
 * `GatewaySession` needs no change to run with no gateway: its transport is an injected `fetchImpl`,
 * and the only request this path makes is one `GET` for a deployment manifest. The implementation below
 * answers exactly that route out of a file named on the command line and refuses every other route by
 * name, so "never from a URL" is a property of this file rather than a promise in a comment, and a
 * receipt pointing its `att.url` at a host does not make this command reach that host.
 *
 * What this command cannot do is stated in its own output rather than left implied: it reads no
 * evidence document, so the platform quote a receipt commits to through `att.d` is not checked here.
 * The receipt's `att.ts` still has to sit inside the policy's evidence window, which is what the
 * printed window names, and the document behind it is fetched by a client that is talking to a
 * deployment, not by this one.
 *
 * The one trust decision a policy file cannot carry, this command takes from the command line.
 * `AshaveriPolicy.manifestKeys` designates the keys whose seal authenticates a deployment manifest,
 * and the policy file format refuses a document naming that field, because every field of a policy is
 * inside its digest and an optional member added there moves the digest of every policy that digest is
 * already cited by. So `--manifest-key` merges a designation into the loaded policy for one run, which
 * is the only way to reach those rules without changing a format. A run that authenticated a manifest
 * on such a key did it with something the digest it prints does not describe, and the report says so
 * rather than leaving it to be inferred: the pin lines name where a designation came from, and both
 * renderings carry the designated keys beside the policy digest.
 *
 * A policy's demand on the material a held slot digests is answerable from this command line. A sealed
 * receipt's `held` slot digests material, and the demand weighs what a reader established about those
 * bytes, so the demand is answerable only where the material is in hand, and two flags put it in hand:
 * `--anchor-file col=<path>` names the document one slot digests and `--anchor-chain col=<path>` the
 * issuer header that arrived beside it, and each pair is appraised exactly the way the pack reader
 * appraises the bytes a container carries. What the pair was checked against is printed with the verdict:
 * the flag and slot that named it, the digest the receipt states, the digest these bytes hash to, the
 * root the answer reached, the window the vendor signed, and the instant the receipt claims, which is the
 * instant the appraisal is asked at because no clock of this run's belongs in that answer. A run handed
 * neither flag answers `ANCHOR_MATERIAL_UNREACHED` under a policy that demands weighed slots: a slot
 * stating `held` is not a claim that some reader can resolve it, and nothing here fetches the bytes to
 * find out.
 */

/**
 * The base a session is built on. It is never a network address: `GatewaySession` appends
 * `/deployment-manifest` to it, and the injected transport below is what answers that one route.
 */
const OFFLINE_BASE_URL = 'ashaveri:offline';

const DIGEST_BYTES = 32;

/** The flags `verify-receipt` reads, typed as the one parse in `cli.ts` produces them. */
export interface VerifyReceiptFlags {
  policy?: string;
  manifest?: string;
  /** Every `--manifest-key` given, unvalidated at this point; see `designatedKeys`. */
  'manifest-key'?: string[];
  nonce?: string;
  'request-body'?: string;
  'request-hash'?: string;
  'response-body'?: string;
  'response-hash'?: string;
  /** One anchor slot's document, as `<slot>=<path>`, repeatable. See `anchorPairs`. */
  'anchor-file'?: string[];
  /** The issuer header that arrived beside one anchor slot's document, as `<slot>=<path>`, repeatable. */
  'anchor-chain'?: string[];
  /** The roots the appraisal stands behind, shared with the pack verbs, and never defaulted to a bundle. */
  'intel-root'?: string[];
  'collateral-origin'?: string[];
  'collateral-platform'?: string[];
  'collateral-cpu-type'?: string[];
  'collateral-level'?: string[];
  now?: string;
  json?: boolean;
}

/** One signing key this run was handed, and the role it was handed for. */
export interface DesignatedKey {
  /** The key's own id: sha256 of its bytes, hex, which is how a seal's `kid` is matched to it. */
  readonly kid: string;
  /** Those bytes in their canonical base64url spelling, which is the form the policy map stores. */
  readonly publicKey: string;
  /** The flag that named this key, printed beside it so a reader sees who designated it. */
  readonly source: string;
}

/** The flag's own name, so a refusal and the report spell it identically. */
export const MANIFEST_KEY_FLAG = '--manifest-key';

/** The flag that designates the keys a signed evidence document is verified under, by kid. */
export const KEY_FLAG = '--key';

/** The one spelling `AshaveriPolicy.manifestKeys` accepts, mirrored from the policy file's `base64Url32`. */
const BASE64URL_32_BYTES = /^[A-Za-z0-9_-]{43}$/u;

/**
 * One designated key argument, read exactly the way the policy file would have read a key.
 *
 * Two channels for one designation have to agree on what a key is or an operator copying a value
 * between them gets two answers, so the three checks are the policy file loader's own: 43 characters
 * of the base64url alphabet, decodable, and equal to the canonical encoding of its own bytes. The
 * last is the one that matters most here, because a designation accepted in a non-canonical spelling
 * would be a key whose id is right and whose text is the one no other reader writes.
 *
 * The id is computed from the key rather than typed beside it, which is what makes the disagreement
 * between a pin and the key filed under it unenterable from a command line.
 */
export function designatedKey(value: string, flag: string): DesignatedKey {
  if (!BASE64URL_32_BYTES.test(value)) {
    throw new UsageError(`${flag} must be the base64url of 32 bytes, which is 43 characters and no padding, not ${JSON.stringify(value)}`);
  }
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(value);
  } catch (err) {
    throw new UsageError(`${flag} is not base64url: ${err instanceof Error ? err.message : String(err)}`);
  }
  const canonical = toBase64Url(bytes);
  if (canonical !== value) {
    throw new UsageError(`${flag} is not the canonical base64url spelling of its own bytes, which are ${canonical}`);
  }
  return { kid: toHex(keyId(bytes)), publicKey: canonical, source: flag };
}

/**
 * The keys this run designates, one per distinct id.
 *
 * Duplicated by id rather than by text: the id is the key's own digest, so two spellings of one key
 * are one designation, and counting it twice would report a check this run did not run twice.
 */
export function designatedKeys(values: readonly string[] | undefined, flag: string): readonly DesignatedKey[] {
  const byKid = new Map<string, DesignatedKey>();
  for (const value of values ?? []) {
    const designation = designatedKey(value, flag);
    byKid.set(designation.kid, designation);
  }
  return [...byKid.values()];
}

/**
 * The policy the session enforces: the document the operator cited, plus what this command line
 * designated.
 *
 * The merge is the asymmetry the report has to disclose. A policy file cannot name a manifest signing
 * key at all, so every key reaching this map came in beside the digest rather than inside it, and a
 * verdict that cites the digest is citing something that covers none of these keys.
 */
function sessionPolicy(policy: AshaveriPolicy, designated: readonly DesignatedKey[]): AshaveriPolicy {
  if (designated.length === 0) return policy;
  return {
    ...policy,
    manifestKeys: {
      ...policy.manifestKeys,
      ...Object.fromEntries(designated.map((each) => [each.kid, each.publicKey])),
    },
  };
}

/**
 * Bytes as typed or piped: `-` is stdin, anything else is one path, and nothing is fetched.
 *
 * Shared with `verify-handover`, which reads one document the same way, because two commands that
 * promise "files only, no URLs" have to keep that promise with one implementation.
 */
export async function readBytes(path: string, label: string): Promise<Uint8Array> {
  if (path === '-') {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(chunk as Buffer);
    }
    return new Uint8Array(Buffer.concat(chunks));
  }
  try {
    return new Uint8Array(await readFile(path));
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new UsageError(`cannot read ${label} '${path}': ${reason}`);
  }
}

/** A flag that decides what this run trusts, named the way the operator has to type it. */
function requiredFlag(value: string | undefined, flag: string, why: string): string {
  if (value === undefined) {
    throw new UsageError(`${flag} is required: ${why}`);
  }
  return value;
}

/**
 * A hex argument, either a digest of exactly `DIGEST_BYTES` or a value of any whole length.
 *
 * The length is checked here rather than downstream because a nonce typed one character short is a
 * different challenge, not a challenge with a leading zero, and a refusal that says which flag was
 * wrong is the only answer that helps whoever typed it.
 */
function parseHexBytes(value: string, flag: string, expectedBytes: number | null): Uint8Array {
  if (!/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
    throw new UsageError(`${flag} must be a hex string of whole bytes`);
  }
  if (expectedBytes !== null && value.length !== expectedBytes * 2) {
    throw new UsageError(`${flag} must be ${expectedBytes * 2} hex digits`);
  }
  return Uint8Array.from({ length: value.length / 2 }, (_, i) => Number.parseInt(value.slice(i * 2, i * 2 + 2), 16));
}

/**
 * The transport `GatewaySession` reads the deployment manifest through.
 *
 * One route answers, and it answers from the bytes this run was handed. Anything else is refused by
 * name, and the refusal names the file the manifest did come from: that message is the evidence that
 * no request left this process, which is what a customer holding a receipt and a policy on a machine
 * with no network is owed.
 */
function offlineTransport(manifestBytes: Uint8Array, manifestPath: string): typeof fetch {
  return async (input: Parameters<typeof fetch>[0]) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : '<a request object>';
    if (!url.endsWith('/deployment-manifest')) {
      throw new Error(
        `offline verification reads files only and reached for ${url}; the deployment manifest was read from '${manifestPath}' and nothing else is fetched`,
      );
    }
    // Named from the bytes rather than from the extension on the file they came from, because a sealed
    // manifest and a plain one travel in files with the same name and the reader decides on the shape.
    // The header is a courtesy here: nothing in the SDK branches on it, and the refusal below is what
    // keeps this transport answering one route out of one file.
    return new Response(manifestBytes, {
      status: 200,
      headers: { 'content-type': isSealedDeploymentManifest(manifestBytes) ? 'application/cose' : 'application/json' },
    });
  };
}

/** How the two digests this run compares were arrived at, in the words the report prints. */
interface Digests {
  readonly requestHash: Uint8Array;
  readonly requestFrom: string;
  readonly responseHash: Uint8Array;
  readonly responseFrom: string;
  /**
   * The response bytes themselves, or null when the caller supplied only their digest. A payload
   * naming a marking needs the bytes themselves; a caller handing over only a digest is refused before this
   * is reached, because its marking claim is read off the bytes and no digest can stand in for them.
   */
  readonly responseBytes: Uint8Array | null;
}

/**
 * The receipt's request and response digests, from the bytes the caller holds or from the digests
 * they wrote down.
 *
 * The bytes win where both are given: a digest copied out of a log and bytes read off a disk are two
 * claims about one conversation, and the one this run can recompute is the one it recomputes. The
 * report names which route supplied each digest either way, because a verdict that quietly trusted a
 * hand-written digest would be reporting less than it checked.
 */
async function digestsOf(values: VerifyReceiptFlags): Promise<Digests> {
  const requestBody = values['request-body'];
  const requestDigest = values['request-hash'];
  let requestHash: Uint8Array;
  let requestFrom: string;
  if (requestBody !== undefined) {
    requestHash = hashRequest(await readBytes(requestBody, '--request-body'));
    requestFrom = `sha256 of the bytes in ${requestBody}`;
  } else if (requestDigest !== undefined) {
    requestHash = parseHexBytes(requestDigest, '--request-hash', DIGEST_BYTES);
    requestFrom = 'the --request-hash value as written';
  } else {
    throw new UsageError(
      'a receipt attests a request and a response, so one of --request-body or --request-hash is required; with neither, the digest inside the receipt has nothing to be compared against',
    );
  }
  const responseBody = values['response-body'];
  const responseDigest = values['response-hash'];
  let responseHash: Uint8Array;
  let responseFrom: string;
  let responseBytes: Uint8Array | null = null;
  if (responseBody !== undefined) {
    responseBytes = await readBytes(responseBody, '--response-body');
    responseHash = hashRequest(responseBytes);
    responseFrom = `sha256 of the bytes in ${responseBody}`;
  } else if (responseDigest !== undefined) {
    responseHash = parseHexBytes(responseDigest, '--response-hash', DIGEST_BYTES);
    responseFrom = 'the --response-hash value as written';
  } else {
    throw new UsageError(
      'a receipt attests a request and a response, so one of --response-body or --response-hash is required; with neither, the digest inside the receipt has nothing to be compared against',
    );
  }
  return { requestHash, requestFrom, responseHash, responseFrom, responseBytes };
}

/** The flag that names the document one anchor slot digests, as `<slot>=<path>`. */
export const ANCHOR_FILE_FLAG = '--anchor-file';

/** The flag that names the issuer header that arrived beside that document, as `<slot>=<path>`. */
export const ANCHOR_CHAIN_FLAG = '--anchor-chain';

/** One anchor slot's material, as the two flags name it. */
interface AnchorPair {
  readonly slot: AnchorSlotLabel;
  readonly filePath: string;
  readonly chainPath: string | null;
}

/**
 * The pairs this run was handed, one per slot `--anchor-file` names.
 *
 * `slotValue` and `once` are the sibling command's own parser, because two verbs read the same two slot labels and a
 * mistyped slot is one mistake rather than two. A header named without its body is refused here instead of being
 * handed to the appraisal: which arm weighs a document is settled by whether a header arrived beside the body it
 * signs, so a lone header is a question about bytes nobody handed over, and a body alone is a question this run
 * answers and says the shape of.
 */
export function anchorPairs(values: VerifyReceiptFlags): readonly AnchorPair[] {
  const pairs = new Map<AnchorSlotLabel, AnchorPair>();
  for (const value of values['anchor-file'] ?? []) {
    const { slot, rest } = slotValue(value, ANCHOR_FILE_FLAG);
    once(ANCHOR_FILE_FLAG, slot, 'document, which is the body a slot digests', pairs.get(slot)?.filePath);
    pairs.set(slot, { slot, filePath: rest, chainPath: null });
  }
  for (const value of values['anchor-chain'] ?? []) {
    const { slot, rest } = slotValue(value, ANCHOR_CHAIN_FLAG);
    const pair = pairs.get(slot);
    if (pair === undefined) {
      throw new UsageError(`${ANCHOR_CHAIN_FLAG} names the '${slot}' slot and ${ANCHOR_FILE_FLAG} names no document for it: a header is weighed beside the body it signs and never in place of it`);
    }
    once(ANCHOR_CHAIN_FLAG, slot, 'header, which is the half that reaches a root', pair.chainPath);
    pairs.set(slot, { ...pair, chainPath: rest });
  }
  return [...pairs.values()];
}

/** One pair, weighed, with every figure the report prints about it. */
export interface AnchorWeighing {
  readonly slot: AnchorSlotLabel;
  readonly filePath: string;
  readonly chainPath: string | null;
  /** The digest the receipt's held slot states, which is the name the reading is filed under. */
  readonly stated: string;
  /** What the bytes handed for that slot hash to, recomputed here rather than copied off a label. */
  readonly resolved: string;
  /** The reading the demand weighs: reached material, both digests, and what the signature stands as. */
  readonly reading: AnchorSlotReading;
  readonly state: CollateralOutcome['state'];
  readonly refusalCode: string | null;
  /** The pinned certificate the chain reached, which is the root this answer stood behind. */
  readonly root: string | null;
  /** Unix seconds: the instant the receipt claims, which is both the held instant and the moment weighed. */
  readonly instant: number;
  readonly question: CarriedQuestion;
}

/**
 * Each pair the flags named, weighed against the roots this run stands behind.
 *
 * The instant is the receipt's own `iat`, which is the rule the sibling command keeps for a container's material:
 * what a record claims it took in is read at the moment that record states, and a clock of this run's would answer
 * a question about today. The digest the slot states is what the reading is filed under and the digest these bytes
 * hash to travels beside it, because bytes answering another digest are a finding about the caller's folder rather
 * than an anchor weighed, and `policy.ts` says that in its own refusal.
 *
 * Two refusals belong to this command line rather than to the appraisal, and both are an operator's typing: a slot
 * the receipt states as an absence names no material for a file to answer to, and a slot no origin and platform flag
 * describes leaves the appraisal no question it could answer. Neither is met by a default here: the sibling command
 * refuses a substituted anchor for the same reason, that a value this file invented is not this caller's pin.
 */
export async function weighAnchorSlots(
  pairs: readonly AnchorPair[],
  anchor: CollateralValidityAnchor,
  designations: CarriedDesignations,
  instant: number,
): Promise<readonly AnchorWeighing[]> {
  const weighed: AnchorWeighing[] = [];
  for (const pair of pairs) {
    const slot = pair.slot === 'col' ? anchor.collateral : anchor.validity;
    if (slot.presence !== 'held') {
      throw new UsageError(`${ANCHOR_FILE_FLAG} names the '${pair.slot}' slot, which this receipt states as an absence (${slot.presence}: ${slot.reason}), so no digest is stated there for these bytes to answer to`);
    }
    const designation = designations.bySlot.get(pair.slot);
    if (designation === undefined) {
      throw new UsageError(`${ANCHOR_FILE_FLAG} names the '${pair.slot}' slot and ${COLLATERAL_ORIGIN_FLAG} and ${COLLATERAL_PLATFORM_FLAG} name no question for it, so nothing can be asked of the bytes handed for it`);
    }
    const bytes = await readBytes(pair.filePath, ANCHOR_FILE_FLAG);
    const chain = pair.chainPath === null ? null : await readBytes(pair.chainPath, ANCHOR_CHAIN_FLAG);
    const stated = toHex(slot.sha256);
    const resolved = toHex(hashRequest(bytes));
    const outcome = await appraiseCarriedCollateral(
      {
        origin: designation.origin,
        platform: designation.platform,
        cpuType: designation.cpuType,
        level: designation.level,
        appraisalAt: instant,
        roots: designations.roots,
        // Never `refuse`, which is the sibling command's rule too: an answer that cannot be reached is a row the
        // reader weighs, and the demand below is the one place a shortage earns a verdict.
        onAbsent: 'unassessed',
      },
      // `chainSha256` is null because nothing states one. A pack's reference carries the digest of the header it
      // attached beside a body; a file named at a command line carries only its own name, so the header travels as
      // it was handed and the report says which file it came from.
      { bytes, chain, chainSha256: null, heldAt: instant },
    );
    const standing = outcome.collateral;
    const refusal = refusalOf(outcome);
    const signature: AnchorSlotReading['signature'] = standing === null
      ? 'not-established'
      : outcome.state === 'revoked'
        ? 'withdrawn'
        : 'established';
    weighed.push({
      slot: pair.slot,
      filePath: pair.filePath,
      chainPath: pair.chainPath,
      stated,
      resolved,
      reading: {
        slot: pair.slot,
        digest: stated,
        reached: true,
        resolvedDigest: resolved,
        signature,
        window: standing === null ? null : standing.classification.window,
      },
      state: outcome.state,
      refusalCode: refusal === null ? null : refusal.code,
      root: standing?.anchorDigest ?? null,
      instant,
      question: {
        origin: designation.origin,
        platform: designation.platform,
        cpuType: designation.cpuType,
        level: designation.level === null ? null : `${designation.level.by}=${designation.level.value}`,
        roots: designations.roots.length,
        from: {
          ...designation.from,
          roots: designations.rootPaths.length === 0
            ? `${INTEL_ROOT_FLAG} named none, and no root bundled with the verifier was consulted`
            : `${INTEL_ROOT_FLAG} ${designations.rootPaths.map((one) => printedToken(one)).join(' and ')}`,
        },
      },
    });
  }
  return weighed;
}

/**
 * Which pin families the policy named, and which it left out.
 *
 * A family the document does not name is not a failure and not a pass: nothing was pinned, so
 * nothing was checked against it. It is reported either way, because an auditor reading a verdict
 * needs to know which of the five questions this run actually asked.
 *
 * Each row carries its own two sentences instead of being built from one template, because the
 * manifest signing keys are the one family a designation can reach without passing through the policy
 * document. A line crediting the policy with a key somebody typed on a command line would cite a
 * digest that covers neither, which is the kind of sentence this report exists not to write.
 */
function pinFamilies(
  policy: AshaveriPolicy,
  designated: readonly DesignatedKey[],
): {
  readonly pinned: readonly string[];
  readonly notPinned: readonly string[];
} {
  const families: ReadonlyArray<readonly [asked: unknown, held: string, notAsked: string]> = [
    [
      policy.issuers,
      "issuer: the policy's 'issuers' pin matched",
      "issuer: the policy names no 'issuers' pin, so nothing was compared",
    ],
    [
      policy.instances,
      "instance: the policy's 'instances' pin matched",
      "instance: the policy names no 'instances' pin, so nothing was compared",
    ],
    [
      policy.keys,
      "receipt key: the policy's 'keys' pin matched",
      "receipt key: the policy names no 'keys' pin, so nothing was compared",
    ],
    [
      designated.length === 0 ? undefined : designated,
      `manifest key: the manifest seal verified under a key designated by ${MANIFEST_KEY_FLAG} on this command line, which no part of the cited policy digest covers`,
      "manifest key: the policy file names no 'manifestKeys' pin and no --manifest-key was given, so no seal was checked",
    ],
    [
      policy.measurements,
      "measurement: the policy's 'measurements' pin matched",
      "measurement: the policy names no 'measurements' pin, so nothing was compared",
    ],
  ];
  const pinned: string[] = [];
  const notPinned: string[] = [];
  for (const [asked, held, notAsked] of families) {
    if (asked === undefined) {
      notPinned.push(notAsked);
    } else {
      pinned.push(held);
    }
  }
  return { pinned, notPinned };
}

function isoOf(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString();
}

/** Everything a report needs, gathered once so the two renderings cannot disagree about it. */
interface Verdict {
  readonly verified: VerifiedReceipt;
  readonly manifestIss: string;
  readonly manifestIns: string;
  readonly manifestEpoch: number;
  readonly manifestKeys: readonly string[];
  /** What the manifest's own declaration said about the epoch this receipt claims, and why. */
  readonly epoch: EpochVerdict;
  /** Whether the document that carried those declarations was authenticated, and the reason it was not. */
  readonly authentication: ManifestAuthentication;
  /** The manifest signing keys this run was handed, with the flag that named each of them. */
  readonly keyDesignation: readonly DesignatedKey[];
  readonly policyDigest: string;
  readonly policyPath: string;
  readonly manifestPath: string;
  readonly nonce: Uint8Array;
  readonly digests: Digests;
  readonly verificationSeconds: number;
  readonly receiptWindow: number;
  readonly evidenceWindow: number;
  readonly pinned: readonly string[];
  readonly notPinned: readonly string[];
  /** One row per pair `--anchor-file` named, with the reading the demand weighed and everything beside it. */
  readonly anchor: readonly AnchorWeighing[];
  /** The root rule of this run, in the sibling command's words, or null where no pair was named. */
  readonly anchorRootRule: string | null;
  /** Roots named at a run that named no slot for them to stand behind, which is a gap in the call, not a pass. */
  readonly rootsNamedWithoutSlot: number;
}

/**
 * The anchor rows: a line per figure a pair was weighed on, and one line naming the roots those weighings stood
 * behind, or the absence where no pair was named. The absence is printed because the demand is answered by material
 * this run reached, and a reader of a verdict has to see that none was rather than infer it from silence.
 */
function anchorLines(verdict: Verdict): readonly string[] {
  if (verdict.anchor.length === 0) {
    const lines = [
      `  anchor material:  no ${ANCHOR_FILE_FLAG} was handed, so no held slot's material was reached and no appraisal ran; a policy demanding weighed slots answers ANCHOR_MATERIAL_UNREACHED rather than passing a slot nothing read`,
    ];
    if (verdict.rootsNamedWithoutSlot > 0) {
      lines.push(`  anchor roots:       ${String(verdict.rootsNamedWithoutSlot)} ${INTEL_ROOT_FLAG} file(s) named here were consulted by nothing, because ${ANCHOR_FILE_FLAG} named no slot for them to stand behind`);
    }
    return lines;
  }
  const lines: string[] = [];
  for (const one of verdict.anchor) {
    lines.push(
      `  anchor file:      ${ANCHOR_FILE_FLAG} ${one.slot}=${one.filePath} for the '${one.slot}' slot, and ${one.chainPath === null
        ? `${ANCHOR_CHAIN_FLAG} named no header for it, so this body is weighed alone`
        : `${ANCHOR_CHAIN_FLAG} ${one.slot}=${one.chainPath} handed beside it, with no digest of that header stated by anything this run reads`}`,
    );
    lines.push(`  anchor digests:   the '${one.slot}' slot states ${one.stated} and these bytes hash to ${one.resolved}${one.stated === one.resolved ? ', the same object' : ', which is not the object the slot names'}`);
    const window = one.reading.window;
    lines.push(
      `  anchor standing:  ${one.reading.signature} (the appraisal answered ${one.state}${one.refusalCode === null ? '' : `, ${one.refusalCode}`}) under the pinned root ${one.root ?? 'none this run reached'}, ${window === null
        ? 'stating no validity window of its own'
        : `standing ${String(window.from)} (${isoOf(window.from)}) up to ${String(window.until)} (${isoOf(window.until)})`}, weighed at ${String(one.instant)} (${isoOf(one.instant)})`,
    );
    lines.push(`  anchor question:  ${one.slot}: ${questionText(one.question)}`);
  }
  lines.push(`  anchor roots:     ${verdict.anchorRootRule ?? 'none named'}`);
  return lines;
}

/**
 * The epoch line, as an adjudication rather than as two numbers standing beside each other.
 *
 * Two numbers that happen to be equal read as a verdict to a reader who did not have to work out what
 * the question was. This is the SDK's answer, in the SDK's words.
 */
function epochLine(verdict: EpochVerdict): string {
  if (!verdict.ok) return `refused (${verdict.code}): ${verdict.detail}`;
  const window =
    verdict.validFrom === null
      ? ''
      : `, window ${verdict.validFrom} to ${String(verdict.validTo ?? 'no published end')}`;
  return `adjudicated against the manifest's declaration (${verdict.basis}${window}): ${verdict.detail}`;
}

function sealLine(authentication: ManifestAuthentication, designated: readonly DesignatedKey[]): string {
  if (!authentication.authenticated) {
    return authentication.advisory ?? 'not authenticated, and no reason was recorded';
  }
  const kid = String(authentication.kid);
  // The key that held the seal is named with the channel it arrived through, because "designated by the
  // policy" and "typed on this command line" are two different amounts of evidence about one document.
  return designated.some((each) => each.kid === authentication.kid)
    ? `sealed, and verified under the manifest key for ${kid}, designated by ${MANIFEST_KEY_FLAG} on this command line`
    : `sealed, and verified under the manifest key designated for ${kid}`;
}

/**
 * The human lines naming what this run trusted beyond its own citation: one per designated key, and
 * one saying plainly that the printed digest covers none of them. Empty when nothing was designated.
 */
function designationLines(designated: readonly DesignatedKey[]): readonly string[] {
  if (designated.length === 0) return [];
  return [
    ...designated.map(
      (each) => `  designated key:   ${each.kid} = ${each.publicKey} (designated by ${each.source} on this command line)`,
    ),
    '  key source:       the policy digest above designates no manifest signing key, so the seal below was checked against what this command line handed over',
  ];
}

function humanVerdict(verdict: Verdict): string {
  const payload = verdict.verified.payload;
  const lines = [
    `receipt verified (COSE_Sign1, payload v${payload.v}, EdDSA over the signed bytes)`,
    `  kid:              ${toHex(verdict.verified.header.kid)}`,
    `  issuer:           ${payload.iss}`,
    `  instance:         ${payload.ins}`,
    `  model:            ${payload.mdl}`,
    `  weights:          ${toHex(payload.wts)}`,
    `  nonce:            ${toHex(verdict.nonce)} (the value this run was told to expect)`,
    `  issued at:        ${payload.iat} (${isoOf(payload.iat)})`,
    `  verified at:      ${verdict.verificationSeconds} (${isoOf(verdict.verificationSeconds)})`,
    `  key epoch:        ${payload.epk}, ${epochLine(verdict.epoch)}`,
    `  measurement:      ${toHex(payload.meas.m)} (${payload.meas.tee})`,
    `  request digest:   ${toHex(payload.req)}, ${verdict.digests.requestFrom}`,
    `  response digest:  ${toHex(payload.res)}, ${verdict.digests.responseFrom}`,
    // Every payload this format reads names a marking, so the line is printed for every verdict this
    // function renders: what the sentence reports is the member, and this run read it off the bytes
    // printed above because naming a marking is what made those bytes a precondition of the run.
    `  marked region:    ${toHex(payload.mk.d)} (${payload.mk.sch}), read off the response bytes above`,
    `  evidence ref:     ${toHex(payload.att.d)} at ${payload.att.ts} (${isoOf(payload.att.ts)})`,
    `  policy:           ${verdict.policyDigest} from ${verdict.policyPath}`,
    ...designationLines(verdict.keyDesignation),
    ...anchorLines(verdict),
    `  manifest:         ${verdict.manifestPath} (issuer ${verdict.manifestIss}, instance ${verdict.manifestIns})`,
    `  manifest seal:    ${sealLine(verdict.authentication, verdict.keyDesignation)}`,
    `  windows:          receipt within ${verdict.receiptWindow} s, evidence timestamp within ${verdict.evidenceWindow} s, both of the verification time`,
    ...verdict.pinned.map((line) => `  pinned:           ${line}`),
    ...verdict.notPinned.map((line) => `  not pinned:       ${line}`),
    '  not checked:      the evidence document behind att.d, which this command does not fetch',
  ];
  return lines.join('\n');
}

function jsonVerdict(verdict: Verdict): Record<string, unknown> {
  const payload = verdict.verified.payload;
  return {
    ok: true,
    format: 'COSE_Sign1',
    payloadVersion: payload.v,
    kid: toHex(verdict.verified.header.kid),
    issuer: payload.iss,
    instance: payload.ins,
    model: payload.mdl,
    weights: toHex(payload.wts),
    nonce: toHex(verdict.nonce),
    issuedAt: payload.iat,
    issuedAtIso: isoOf(payload.iat),
    verifiedAt: verdict.verificationSeconds,
    verifiedAtIso: isoOf(verdict.verificationSeconds),
    keyEpoch: {
      receipt: payload.epk,
      manifest: verdict.manifestEpoch,
      accepted: verdict.epoch.ok,
      basis: verdict.epoch.ok ? verdict.epoch.basis : null,
      validFrom: verdict.epoch.ok ? verdict.epoch.validFrom : null,
      validTo: verdict.epoch.ok ? verdict.epoch.validTo : null,
      superseded: verdict.epoch.ok ? verdict.epoch.superseded : null,
      reason: verdict.epoch.detail,
      ...(verdict.epoch.ok ? {} : { code: verdict.epoch.code }),
    },
    manifestSeal: {
      sealed: verdict.authentication.sealed,
      authenticated: verdict.authentication.authenticated,
      kid: verdict.authentication.kid,
      policyDesignatesManifestKey: verdict.authentication.demanded,
      advisory: verdict.authentication.advisory,
    },
    measurement: { tee: payload.meas.tee, m: toHex(payload.meas.m) },
    requestDigest: { sha256: toHex(payload.req), takenFrom: verdict.digests.requestFrom },
    responseDigest: { sha256: toHex(payload.res), takenFrom: verdict.digests.responseFrom },
    markedRegion: { scheme: payload.mk.sch, sha256: toHex(payload.mk.d) },
    evidence: { digest: toHex(payload.att.d), timestamp: payload.att.ts, documentChecked: false },
    policy: { digest: verdict.policyDigest, file: verdict.policyPath },
    // Where every manifest signing key this run checked a seal against came from, printed beside the
    // digest that covers none of them. A policy file has no field for such a key, so a non-empty list
    // here is a statement about this run's inputs, not a warning about the deployment.
    manifestKeyDesignation: verdict.keyDesignation.map((each) => ({
      kid: each.kid,
      publicKey: each.publicKey,
      source: each.source,
    })),
    manifestKeyDesignationOutsidePolicyDigest: verdict.keyDesignation.length > 0,
    // One object per pair this run weighed, each naming the flag that handed it, the digest the receipt states, the
    // digest these bytes hash to, the root the answer reached and the instant it was read at. An empty list is the
    // absence the human rendering prints, and a demanding policy refuses it, so it is never read as a pass.
    anchorMaterialNamed: verdict.anchor.length > 0,
    anchorMaterial: verdict.anchor.map((one) => ({
      flag: ANCHOR_FILE_FLAG,
      slot: one.slot,
      file: one.filePath,
      chain: one.chainPath === null ? null : { flag: ANCHOR_CHAIN_FLAG, file: one.chainPath },
      statedDigest: one.stated,
      resolvedDigest: one.resolved,
      reached: one.reading.reached,
      signature: one.reading.signature,
      window: one.reading.window,
      rootDigest: one.root,
      state: one.state,
      refusalCode: one.refusalCode,
      appraisalAt: one.instant,
      question: {
        origin: one.question.origin,
        platform: one.question.platform,
        cpuType: one.question.cpuType,
        level: one.question.level,
      },
    })),
    anchorRootRule: verdict.anchorRootRule,
    anchorRootsNamedWithoutSlot: verdict.rootsNamedWithoutSlot,
    manifest: {
      file: verdict.manifestPath,
      issuer: verdict.manifestIss,
      instance: verdict.manifestIns,
      declaredKeys: verdict.manifestKeys,
    },
    windows: { receiptSeconds: verdict.receiptWindow, evidenceSeconds: verdict.evidenceWindow },
    pinned: verdict.pinned,
    notPinned: verdict.notPinned,
    notChecked: ['the evidence document behind att.d, which this command does not fetch'],
  };
}

/** The one failure shape: the code rather than a sentence, with the message beside it. */
function refuse(err: SdkError | ReceiptError, json: boolean): number {
  if (json) {
    writeJson({ ok: false, code: err.code, message: err.message });
  } else {
    process.stderr.write(`verification failed (${err.code}): ${escapeInvisible(err.message)}\n`);
  }
  return 1;
}

/** `ashaveri verify-receipt <receipt> [options]`, including its exit codes. */
export async function runVerifyReceipt(positionals: string[], values: VerifyReceiptFlags): Promise<number> {
  if (positionals.length !== 1) {
    throw new UsageError("expected exactly one argument: 'verify-receipt <receipt>'");
  }
  const receiptPath = positionals[0] as string;
  const policyPath = requiredFlag(
    values.policy,
    '--policy',
    'a receipt means what its pins make it mean, and this command trusts nothing it was not handed',
  );
  const manifestPath = requiredFlag(
    values.manifest,
    '--manifest',
    'the key a receipt was signed with is accepted by matching it against the deployment manifest that declares it',
  );
  const nonce = parseHexBytes(
    requiredFlag(
      values.nonce,
      '--nonce',
      'a receipt answers one challenge, and a verdict about no challenge is a verdict about some other request',
    ),
    '--nonce',
    null,
  );
  // Refused here rather than at the check itself: an argument that is not a key is a typing mistake,
  // and it is one before this run has read a byte of anybody's material.
  const designations = designatedKeys(values['manifest-key'], MANIFEST_KEY_FLAG);
  // The anchor pairs are parsed, and their roots and designations read, before any document is opened: a slot that
  // is not a slot, a header with no body beside it and an origin with no platform are the caller's typing to fix,
  // and none of them becomes a verdict about a receipt.
  const pairs = anchorPairs(values);
  const carried = pairs.length === 0 ? null : await carriedDesignations(values);
  const loaded = await readPolicyFile(policyPath);
  const receiptBytes = await readBytes(receiptPath, 'receipt');
  const manifestBytes = await readBytes(manifestPath, '--manifest');
  const digests = await digestsOf(values);
  let nowMillis: number | undefined;
  if (values.now !== undefined) {
    nowMillis = Date.parse(values.now);
    if (Number.isNaN(nowMillis)) {
      throw new UsageError(`--now is not a valid date: ${values.now}`);
    }
  }

  // The payload is read before it is verified, which is what `GatewaySession.verifyReceipted` does
  // of its own accord, so this opens no second window onto unverified bytes. It settles one input
  // question: every payload this format reads names a marking attesting one region inside the
  // response, and the only thing that can answer whether the mark is the attested one is the response
  // itself. Taking a digest in its place would answer "was this the marked response?" with "the caller
  // says so", and no version of this document is allowed to be silent about a mark.
  let anchor: readonly AnchorWeighing[] = [];
  let anchorReadings: readonly AnchorSlotReading[] = [];
  try {
    const opened = decodeReceipt(receiptBytes);
    if (digests.responseBytes === null) {
      throw new UsageError(
        'this receipt names a marking attesting one region inside the response bytes, so --response-body is required and --response-hash cannot carry that check',
      );
    }
    // Two figures of this payload file the readings: the digest each held slot states, and the stamp the document
    // claims. Nothing is trusted from this read, because the client re-reads both off the bytes it verifies, and a
    // reading that does not line up with what the verified payload states is answered as unreached or as the wrong
    // bytes. What is weighed here is a file this command line named, so no byte of the receipt reaches the appraisal.
    anchor = carried === null ? [] : await weighAnchorSlots(pairs, opened.payload.cva, carried, opened.payload.iat);
    anchorReadings = anchor.map((one) => one.reading);
  } catch (err) {
    if (err instanceof ReceiptError) {
      return refuse(err, values.json === true);
    }
    throw err;
  }

  const session = new GatewaySession(OFFLINE_BASE_URL, {
    fetchImpl: offlineTransport(manifestBytes, manifestPath),
    // The keys this command line designated join the loaded policy here, which is the only place they
    // are ever joined: every check below, the receipt's pins and the manifest's seal alike, reads the
    // one policy the session holds, so no rule sees a designation the others do not.
    policy: sessionPolicy(loaded.policy, designations),
  });
  try {
    const verified = await session.verifyReceipted({
      receiptBytes,
      nonce,
      requestHash: digests.requestHash,
      responseHash: digests.responseHash,
      responseBytes: digests.responseBytes,
      nowMillis,
      // The client's own demand reads these, which is the only reason they are handed at all: a policy naming no
      // demand never looks at them, and a run that named no pair hands an empty list and is answered as unreached.
      anchorReadings,
    });
    const manifest = await session.manifest();
    const authentication = await session.manifestAuthentication();
    const epoch = await session.adjudicateEpoch({
      kid: toHex(verified.header.kid),
      epoch: verified.payload.epk,
      issuedAt: verified.payload.iat,
    });
    if (!epoch.ok) {
      // Unreachable through a verification that held, since the two read one cached manifest through
      // one function, and written anyway because a report that printed an adjudication it did not have
      // is the failure this command exists to make impossible.
      return refuse(
        new SdkError(epoch.code, `the epoch adjudication and the verification that just passed disagree: ${epoch.detail}`),
        values.json === true,
      );
    }
    const families = pinFamilies(loaded.policy, designations);
    const verdict: Verdict = {
      verified,
      manifestIss: manifest.iss,
      manifestIns: manifest.ins,
      manifestEpoch: manifest.epk,
      manifestKeys: manifest.keys.map((key) => key.kid),
      epoch,
      authentication,
      keyDesignation: designations,
      policyDigest: loaded.digest,
      policyPath,
      manifestPath,
      nonce,
      digests,
      verificationSeconds: Math.floor((nowMillis ?? Date.now()) / 1000),
      receiptWindow: loaded.policy.maxReceiptAgeSeconds ?? DEFAULT_MAX_RECEIPT_AGE_SECONDS,
      evidenceWindow: loaded.policy.maxEvidenceAgeSeconds ?? DEFAULT_MAX_EVIDENCE_AGE_SECONDS,
      pinned: families.pinned,
      notPinned: families.notPinned,
      anchor,
      anchorRootRule: carried === null ? null : rootRule(carried),
      rootsNamedWithoutSlot: carried === null ? (values['intel-root'] ?? []).length : 0,
    };
    if (values.json) {
      writeJson(jsonVerdict(verdict));
    } else {
      process.stdout.write(`${humanVerdict(verdict)}\n`);
    }
    return 0;
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) {
      return refuse(err, values.json === true);
    }
    throw err;
  }
}
