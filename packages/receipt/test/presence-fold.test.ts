import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  decodeEpochInventory,
  signEpochInventory,
  toHex,
  verifyEpochInventory,
  type EpochInventoryPresence,
} from '../src/index.js';
import {
  FOLD_GAP,
  FOLD_HONEST,
  FOLD_KEY,
  FOLD_LATE,
  FOLD_RUN_START,
  FOLD_WINDOW,
  HELD,
  HELD_COLLATERAL,
  HELD_VALIDITY,
  artifact,
  buildRun,
  foldDigest,
  foldReadWith,
  foldRefusal,
  sealFoldDocument,
  sealOf,
} from './presence-run.js';

/**
 * The presence fold: the interval across which a store reported holding the appraisal context, computed at the
 * read and stored in neither document.
 *
 * The inventory states which manifests a run seals and what its packs add up to. A retention manifest states
 * which collateral and validity digests one store held at the instant it stamped, and carries none of those
 * bytes. Neither document can say whether the period the inventory attests is a period the material was there,
 * and a figure restated inside the signature from evidence the signature does not carry would make one fact the
 * property of two owners, so the interval arrives only for the reader that holds both, asked of the bytes the run
 * itself sealed. What this file is for is the parts of that no single document answers: which number the
 * arithmetic put on the page, which of the three refusals a given pair of artifacts reaches, and what the common
 * call still answers when it hands nothing.
 *
 * The refusals are asked one per branch, and the branches are told apart by the reader's own sentence rather than
 * by a code two faults share, which is the pattern the two folded lists already work to. Three findings share
 * `EPOCH_INVENTORY_PRESENCE_UNSEALED`, because the action is one action whatever arrived: hand the files the
 * entries name. Each of the three opens its detail with the words that say which it found, and the bound a quoted
 * detail is cut at is read out of the registry rather than remembered here, because a finding named past the cut
 * is a finding nobody can act on.
 *
 * The runs and the manifests come from `presence-run.ts`, which writes them with this package's own retention
 * writer, so every digest the fold matches is one a manifest actually hashes to. A case typed with hand-made hex
 * would let a fold that never looked at the bytes pass, which is the exact fault the layout's own note about a
 * bare retention file is there to keep visible.
 */

const registrySource = readFileSync(fileURLToPath(new URL('../src/errors.ts', import.meta.url)), 'utf8');

/** The width the registry cuts a quoted detail at, read out of the registry rather than restated here. */
const DETAIL_BOUND = (() => {
  const stated = /MAX_DETAIL = (\d+)/u.exec(registrySource);
  if (stated === null) throw new Error('the registry states no detail bound to measure a finding against');
  return Number(stated[1]);
})();

/** The fixed sentence of one code, with the separator the reader puts between it and the detail. */
function fixedSentence(code: string): string {
  const stated = new RegExp(`^  ${code}: '([^']+)'`, 'mu').exec(registrySource);
  if (stated === null) throw new Error(`${code} carries no fixed sentence in the registry`);
  return `${stated[1]}: `;
}

/** The detail a reader is handed: the message past its fixed sentence, kept to the width the registry keeps. */
function quotedDetail(message: string, head: string): string {
  return message.slice(head.length, head.length + DETAIL_BOUND);
}

describe('the presence fold of an epoch inventory', () => {
  it('answers with the interval the observations themselves reach, and the digests they named', () => {
    const read = verifyEpochInventory(sealOf(FOLD_HONEST), foldReadWith(FOLD_HONEST.artifacts));
    const presence = read.outcome.presence;
    expect(presence, 'a call that handed the run\'s manifests got no folded interval back').toBeDefined();
    expect(presence).toEqual({
      from: FOLD_HONEST.manifest.window.from,
      to: FOLD_HONEST.manifest.window.to,
      observations: 3,
      collateral: [HELD_COLLATERAL],
      validity: [HELD_VALIDITY],
    });
    // The figure is the arithmetic of the observations rather than a quotation of the stated window, and the two
    // agree here because the fold refuses every answer where they do not: the count is the entries that
    // contributed, which is the run\'s own length wherever the fold speaks at all.
    expect(presence?.from, 'the interval opens somewhere other than where the run opens').toBe(read.manifest.window.from);
    expect(presence?.to).toBe(read.manifest.window.to);
    expect(presence?.observations).toBe(read.outcome.packs.length);
  });

  it('keeps one digest in two families apart rather than merging it into one claim', () => {
    // The same bytes can be both the root a quote chains to and the document an appraisal was read under, and the
    // two statements are about different material. A fold keyed on the digest alone would report one entry where
    // the store said two, and would let either family answer for the absence of the other.
    const shared = foldDigest('a document that is both collateral and validity');
    const both = buildRun(3, () => ({ collateral: [shared], validity: [shared] }));
    const presence = verifyEpochInventory(sealOf(both), foldReadWith(both.artifacts)).outcome.presence as EpochInventoryPresence;
    expect(presence.collateral, 'the collateral roster lost the shared digest').toEqual([shared]);
    expect(presence.validity, 'the validity roster lost the shared digest').toEqual([shared]);
    expect(presence.observations, 'one manifest counted twice because it named the same bytes twice').toBe(3);
  });

  it('lists each family sorted, so the roster a caller prints is the roster the fold holds', () => {
    const later = foldDigest('the root held since the second window');
    const earlier = foldDigest('the root held since the first window');
    const two = buildRun(3, () => ({ collateral: [later, earlier], validity: [HELD_VALIDITY] }));
    const presence = verifyEpochInventory(sealOf(two), foldReadWith(two.artifacts)).outcome.presence as EpochInventoryPresence;
    expect(presence.collateral).toEqual([later, earlier].sort());
    expect(presence.validity).toEqual([HELD_VALIDITY]);
  });

  it('answers a call that hands nothing exactly as it answered before the fold existed', () => {
    // The optional input is the whole of the difference between the two calls below, and this is the proof rather
    // than an assertion of it: the same bytes, the same key, the same run handed back, no folded interval standing
    // on the outcome as a figure of zero, and no new refusal on a document the fold has nothing to say about.
    const bytes = signEpochInventory(FOLD_HONEST.manifest, FOLD_KEY);
    const bare = verifyEpochInventory(bytes, foldReadWith());
    expect('presence' in bare.outcome, 'a call that handed no manifest came back with an interval anyway').toBe(false);
    expect(bare.outcome.presence).toBeUndefined();
    expect(Object.keys(bare.outcome)).toEqual(['packs']);
    expect(decodeEpochInventory(bytes).manifest).toEqual(bare.manifest);
    // And the document the fold refuses for want of evidence is accepted by the reader that was handed none, which
    // is what makes every refusal below about the pair of inputs rather than about the bytes under the signature.
    expect(foldRefusal(() => verifyEpochInventory(sealFoldDocument(FOLD_GAP.manifest), foldReadWith(FOLD_GAP.artifacts))).code).toBe(
      'EPOCH_INVENTORY_PRESENCE_GAP',
    );
    expect(foldRefusal(() => verifyEpochInventory(sealFoldDocument(FOLD_GAP.manifest), foldReadWith())).code).toBe('accepted');
    expect(foldRefusal(() => decodeEpochInventory(sealFoldDocument(FOLD_GAP.manifest))).code).toBe('accepted');
  });

  it('refuses an observation arriving under a digest no entry of the run seals', () => {
    const foreign = artifact(FOLD_RUN_START + 4 * FOLD_WINDOW + 10, HELD());
    const seen = foldRefusal(() => verifyEpochInventory(sealOf(FOLD_HONEST), foldReadWith([...FOLD_HONEST.artifacts, foreign])));
    expect(seen.code).toBe('EPOCH_INVENTORY_PRESENCE_UNSEALED');
    expect(seen.message.startsWith(`${fixedSentence('EPOCH_INVENTORY_PRESENCE_UNSEALED')}no entry of the run seals`)).toBe(true);
    // Nothing of the observation is read before the digest is settled, so a file of another deployment cannot
    // reach a member of this document at all: these bytes name the material the honest entries name, and the
    // refusal is about the file, which the detail gives as a digest of its own bytes rather than of those names.
    expect(seen.message).not.toContain(HELD_VALIDITY);
    expect(seen.message).toContain(toHex(sha256(foreign)));
  });

  it('refuses one sealed digest handed twice, which counts one pack\'s observation as two', () => {
    const [first] = FOLD_HONEST.artifacts;
    if (first === undefined) throw new Error('the honest run holds no manifest to hand twice');
    const seen = foldRefusal(() => verifyEpochInventory(sealOf(FOLD_HONEST), foldReadWith([...FOLD_HONEST.artifacts, first])));
    expect(seen.code).toBe('EPOCH_INVENTORY_PRESENCE_UNSEALED');
    expect(seen.message.startsWith(`${fixedSentence('EPOCH_INVENTORY_PRESENCE_UNSEALED')}handed twice`)).toBe(true);
  });

  it('refuses one sealed digest stated by two entries, which names no pack the observation belongs to', () => {
    // Two entries of one run sealing the same manifest is one store state claimed for two windows, and the
    // observation arriving under it answers to neither of them on its own.
    const [first, second] = FOLD_HONEST.artifacts;
    if (first === undefined || second === undefined) throw new Error('the honest run holds two manifests to state once');
    const stated = toHex(sha256(first));
    const packs = FOLD_HONEST.manifest.packs.map((one, index) => (index === 1 ? { ...one, retentionSha256: stated } : one));
    const seen = foldRefusal(() => verifyEpochInventory(sealFoldDocument({ ...FOLD_HONEST.manifest, packs }), foldReadWith([first, second, ...FOLD_HONEST.artifacts.slice(2)])));
    expect(seen.code).toBe('EPOCH_INVENTORY_PRESENCE_UNSEALED');
    expect(seen.message.startsWith(`${fixedSentence('EPOCH_INVENTORY_PRESENCE_UNSEALED')}sealed twice`)).toBe(true);
    // The other two entries still seal their own manifests, so this is reached by the digest the run states twice
    // rather than by the file the run does not state at all, and the two sentences say which of the two it was.
    expect(seen.message).not.toContain('no entry of the run seals');
  });

  it('refuses a gap inside the period the inventory attests, and names the window that says nothing', () => {
    const seen = foldRefusal(() => verifyEpochInventory(sealFoldDocument(FOLD_GAP.manifest), foldReadWith(FOLD_GAP.artifacts)));
    expect(seen.code).toBe('EPOCH_INVENTORY_PRESENCE_GAP');
    // The finding leads the sentence: the family, then the digest, then the window between the two that name it.
    // The two places that do name it are the part an operator cannot act on, and they are what a cut detail loses.
    const head = fixedSentence('EPOCH_INVENTORY_PRESENCE_GAP');
    expect(seen.message.startsWith(`${head}collateral digest ${HELD_COLLATERAL} is missing from packs/`)).toBe(true);
    const quoted = quotedDetail(seen.message, head);
    expect(quoted, 'the silent window is named past the bound a quoted detail reaches').toContain(FOLD_GAP.manifest.packs[1]?.file ?? 'nothing');
    // The windows of this run meet end to start, so this is not the contiguity refusal and says something else:
    // the packs cover the period and the store\'s own reporting of the material goes silent inside it.
    expect(seen.code).not.toBe('EPOCH_INVENTORY_RUN_NOT_CONTIGUOUS');
    expect(foldRefusal(() => verifyEpochInventory(sealFoldDocument(FOLD_GAP.manifest), foldReadWith())).code).toBe('accepted');
  });

  it('refuses a stated window wider than the observations reach, and gives both figures', () => {
    // The first entry\'s manifest is whole under the older layout and states no observation, so the evidence
    // begins one window late: the document attests a period the fold cannot show the material through.
    const seen = foldRefusal(() => verifyEpochInventory(sealFoldDocument(FOLD_LATE.manifest), foldReadWith(FOLD_LATE.artifacts)));
    expect(seen.code).toBe('EPOCH_INVENTORY_PRESENCE_WINDOW_TOO_WIDE');
    const head = fixedSentence('EPOCH_INVENTORY_PRESENCE_WINDOW_TOO_WIDE');
    const quoted = quotedDetail(seen.message, head);
    expect(quoted, 'the stated period is not in the detail an operator is handed').toContain(
      `the run states the window ${String(FOLD_RUN_START)} to ${String(FOLD_RUN_START + 3 * FOLD_WINDOW)}`,
    );
    expect(quoted, 'the period the observations reach is not in the detail an operator is handed').toContain(
      `attest ${String(FOLD_RUN_START + FOLD_WINDOW)} to ${String(FOLD_RUN_START + 3 * FOLD_WINDOW)}`,
    );
    expect(seen.code).not.toBe('EPOCH_INVENTORY_SUMMARY_DISAGREES');
  });

  it('refuses a fold whose observations name nothing at all, which is the same finding by the same code', () => {
    // A run of nothing but the layout that states no presence: there is no interval to intersect, and the honest
    // answer is that nothing is attested rather than an interval of zero invented out of the absence of evidence.
    const silent = buildRun(2, () => undefined);
    const seen = foldRefusal(() => verifyEpochInventory(sealFoldDocument(silent.manifest), foldReadWith(silent.artifacts)));
    expect(seen.code).toBe('EPOCH_INVENTORY_PRESENCE_WINDOW_TOO_WIDE');
    expect(seen.message).toContain('name no digest at all');
  });

  it('leaves a manifest its own reader refuses to the retention reader, rather than calling it a fold finding', () => {
    // The fold parses the bytes it admitted, and a sealed digest over a document that is malformed is the
    // manifest\'s fault and not the pair\'s. Two codes answer here for two different files to go and look at.
    const broken = new TextEncoder().encode('{"v": 2, "at": 1}\n');
    const packs = FOLD_HONEST.manifest.packs.map((one, index) => (index === 0 ? { ...one, retentionSha256: toHex(sha256(broken)) } : one));
    const rest = FOLD_HONEST.artifacts.slice(1);
    if (rest.length !== 2) throw new Error('the honest run lost an artifact beside the one this case replaces');
    const seen = foldRefusal(() => verifyEpochInventory(sealFoldDocument({ ...FOLD_HONEST.manifest, packs }), foldReadWith([broken, ...rest])));
    expect(seen.code).toBe('RETENTION_BAD_DOCUMENT');
  });

  it('refuses at the writer what it refuses at the reader, and refuses before any byte is signed', () => {
    const seen = foldRefusal(() => signEpochInventory(FOLD_GAP.manifest, FOLD_KEY, FOLD_GAP.artifacts));
    expect(seen.code).toBe('EPOCH_INVENTORY_PRESENCE_GAP');
    // A writer handed nothing signs exactly what it signed before the fold existed, and a writer handed a coherent
    // set signs the same document: the signature covers the manifest, and the interval is not in it either way.
    const bare = signEpochInventory(FOLD_HONEST.manifest, FOLD_KEY);
    expect(signEpochInventory(FOLD_HONEST.manifest, FOLD_KEY)).toEqual(bare);
    expect(sealOf(FOLD_HONEST)).toEqual(bare);
    expect(foldRefusal(() => verifyEpochInventory(bare, foldReadWith(FOLD_HONEST.artifacts))).code).toBe('accepted');
  });

  it('tells the three fold refusals apart by the reader\'s own sentence and not by a shared code', () => {
    const sentences = [
      'EPOCH_INVENTORY_PRESENCE_UNSEALED',
      'EPOCH_INVENTORY_PRESENCE_GAP',
      'EPOCH_INVENTORY_PRESENCE_WINDOW_TOO_WIDE',
    ].map((code) => fixedSentence(code));
    expect(new Set(sentences).size, 'two of the fold refusals answer with one sentence').toBe(sentences.length);
    for (const one of sentences) {
      expect(one.length, `${one}runs past the bound a quoted detail reaches, so its code is all a reader gets`).toBeLessThan(
        DETAIL_BOUND,
      );
    }
    // And the three findings that share the unsealed code are told apart at the head of the detail, which is the
    // only place a quoted refusal keeps them apart.
    const unsealed = fixedSentence('EPOCH_INVENTORY_PRESENCE_UNSEALED');
    const findings = ['no entry of the run seals', 'sealed twice', 'handed twice'];
    expect(new Set(findings).size).toBe(findings.length);
    for (const one of findings) {
      expect(unsealed.length + one.length, `${one} is named past the bound a quoted detail reaches`).toBeLessThan(DETAIL_BOUND);
    }
  });
});
