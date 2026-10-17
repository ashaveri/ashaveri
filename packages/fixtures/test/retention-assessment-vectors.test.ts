import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ReceiptError } from '@ashaveri/receipt';
import { assessRetention, parseRetentionAssessment, SdkError } from '@ashaveri/sdk';
import { describe, expect, it } from 'vitest';
import { loadRetentionAssessmentVectors, type RetentionAssessmentVectorFile } from '../src/index.js';
import { readSourceFile, unionMembers } from './doc-contract.js';

/**
 * The published retention assessment vectors, replayed the way a port replays them: take the document out
 * of the file, hand it to the two published steps, and compare the answer with the answer the file states.
 * Nothing here computes an expected outcome from a rule written again in this file; the outcomes, the
 * coverage results, the ranges, the reasons and the refusal sentences are data in
 * `data/retention-assessment-v1.json`, and the only question asked of the shipped code is whether it
 * answers as the file says it does. Each published row is a test of its own, so a row that is not
 * replayed has to be skipped rather than silently pass.
 *
 * Three more things are checked on the way. The first is that every refusal refuses at the step the row
 * names, because a reader that took a document a row states as refused would leave that row silent and a
 * refusal moved from the layout to the reading would leave the row describing a fault it does not have.
 * The second is that no code the shipped reader raises is left unreached, read out of the source file
 * rather than copied here. The third is the distinction the suite exists for: one row is a period the
 * sequence evidence genuinely covers and one is a span-only input the old span rule would have called
 * met, and a script has to be able to tell them apart by their published outcomes.
 */

const file: RetentionAssessmentVectorFile = loadRetentionAssessmentVectors();
const VECTORS_DOC = fileURLToPath(new URL('../../../docs/vectors.md', import.meta.url));
const READER_SOURCE = '../../sdk/src/retention-assessment.ts';
const SDK_ERRORS = '../../sdk/src/errors.ts';
const RECEIPT_ERRORS = '../../receipt/src/errors.ts';

type Block = Record<string, unknown>;

const scopeOf = (document: Block): Block => document['scope'] as Block;
const coverageOf = (document: Block): Block => document['coverage'] as Block;

/** What a shipped step answered: its code and its sentence, or `ok` where it answered by handing something back. */
function answered(run: () => unknown): { readonly outcome: string; readonly message: string } {
  try {
    run();
    return { outcome: 'ok', message: '' };
  } catch (err) {
    if (err instanceof SdkError || err instanceof ReceiptError) return { outcome: err.code, message: err.message };
    throw err;
  }
}

function vectorNamed(name: string) {
  const found = file.vectors.find((one) => one.name === name);
  if (found === undefined) throw new Error(`data/retention-assessment-v1.json publishes no row named ${name}`);
  return found;
}

/** The Retention assessment bullet of `docs/vectors.md`, read as one run of prose because its sentences wrap. */
function assessmentBullet(): string {
  const doc = readFileSync(VECTORS_DOC, 'utf8');
  const start = doc.indexOf('\n- **Retention assessment.');
  if (start < 0) throw new Error('docs/vectors.md states no Retention assessment bullet to read');
  const end = doc.indexOf('\n## ', start);
  return doc.slice(start, end < 0 ? undefined : end).replace(/\n\s*/gu, ' ');
}

/** One count that bullet states about these rows, taken back out of the sentence that states it. */
function countInBullet(states: RegExp, what: string): number {
  const stated = states.exec(assessmentBullet());
  if (stated === null) throw new Error(`the Retention assessment bullet of docs/vectors.md states no count of ${what}`);
  return Number(stated[1]);
}

/**
 * The codes the published source file raises itself, read out of the call forms that name one rather than
 * copied into this file. A code the reader raises and no row reaches is a refusal published nowhere.
 */
function codesTheReaderRaises(): string[] {
  const source = readSourceFile(READER_SOURCE);
  const patterns = [
    /refused\(\s*'([A-Z][A-Z0-9_]+)'/gu,
    /new SdkError\(\s*'([A-Z][A-Z0-9_]+)'/gu,
    /new ReceiptError\(\s*'([A-Z][A-Z0-9_]+)'/gu,
  ];
  const found = patterns.flatMap((pattern) => [...source.matchAll(pattern)].map((each) => each[1]!));
  return [...new Set(found)].sort();
}

describe('data/retention-assessment-v1.json', () => {
  it('states a rule in prose, names the two readers it is read by, and publishes both directions', () => {
    expect(file.version).toBe(1);
    expect(file.description.length).toBeGreaterThan(80);
    expect(file.layout.schema).toContain('packages/sdk/schemas/retention-assessment-v1.schema.json');
    expect(file.layout.reader).toContain('parseRetentionAssessment');
    expect(file.layout.reader).toContain('assessRetention');
    expect(file.vectors.length, 'a suite with too few assessment rows cannot state what coverage is').toBeGreaterThanOrEqual(8);
    expect(file.refusals.length, 'a suite of assessed rows proves nothing about a reader\'s refusals').toBeGreaterThanOrEqual(8);
    for (const code of file.layout.codes) {
      expect(file.refusals.some((one) => one.code === code), `${code} is listed and refused by no row`).toBe(true);
    }
  });

  it.each(file.vectors)('$name replays as the file says', (row) => {
    const parsed = answered(() => parseRetentionAssessment(row.document));
    const reading = answered(() => assessRetention(row.document));
    expect(parsed.outcome, `${row.name}: the layout refused a row this file publishes as taken`).toBe('ok');
    expect(reading.outcome, `${row.name}: the reading refused a row this file publishes as taken`).toBe('ok');
    const seen = assessRetention(row.document);
    expect(seen.outcome, `${row.name}: a different outcome for the same evidence`).toBe(row.assessment.outcome);
    expect(seen.coverage.result, `${row.name}: a different coverage result`).toBe(row.assessment.coverage.result);
    expect(seen.coverage.basis, `${row.name}: a different coverage basis`).toBe(row.assessment.coverage.basis);
    expect(seen.coverage.ranges, `${row.name}: different coverage ranges`).toEqual(row.assessment.coverage.ranges);
    expect(seen.coverage.reasons, `${row.name}: different coverage reasons`).toEqual(row.assessment.coverage.reasons);
    expect(seen.reasons, `${row.name}: different assessment reasons`).toEqual(row.assessment.reasons);
  });

  it.each(file.refusals)('$name replays as the file says', (row) => {
    const parsed = answered(() => parseRetentionAssessment(row.document));
    const reading = answered(() => assessRetention(row.document));
    expect(reading.outcome, `${row.name}: the reader took a document this row states as refused`).not.toBe('ok');
    const given = parsed.outcome === 'ok' ? reading : parsed;
    expect(given.outcome, `${row.name}: the reader answers ${given.outcome}, not the ${row.code} the file states`).toBe(
      row.code,
    );
    expect(given.message, `${row.name}: this reader gave the refusal in other words than the file states`).toBe(
      row.message,
    );
  });

  it('refuses every published refusal at the step the row names', () => {
    for (const row of file.refusals) {
      const parsed = answered(() => parseRetentionAssessment(row.document));
      const reading = answered(() => assessRetention(row.document));
      if (row.stage === 'layout') {
        expect(parsed.outcome, `${row.name}: the layout took a document this row states it refuses`).not.toBe('ok');
        expect(parsed.outcome, `${row.name}: the layout answered another code than the row states`).toBe(row.code);
        expect(reading.outcome, `${row.name}: the reading answered before the layout had`).toBe(row.code);
        expect(reading.message, `${row.name}: the two published steps gave two sentences for one fault`).toBe(row.message);
        continue;
      }
      expect(parsed.outcome, `${row.name}: the layout refused the document this row states the reading refuses`).toBe('ok');
      expect(reading.outcome, `${row.name}: the reading took a document this row states it refuses`).toBe(row.code);
      expect(reading.message, `${row.name}: the reading gave another sentence than the row states`).toBe(row.message);
    }
  });

  it('reaches every code the reader raises and names no code no registry declares', () => {
    const raised = codesTheReaderRaises();
    expect(raised.length, 'the reader source names no code, so this check guards nothing').toBeGreaterThanOrEqual(3);
    const reached = new Set(file.refusals.map((one) => one.code));
    for (const code of raised) {
      expect(reached.has(code), `${code} is raised by the shipped reader and no published row reaches it`).toBe(true);
    }
    const declared = new Set([
      ...unionMembers('SdkErrorCode', SDK_ERRORS),
      ...unionMembers('ReceiptErrorCode', RECEIPT_ERRORS),
    ]);
    const undeclared = [...reached].filter((code) => !declared.has(code));
    expect(undeclared, 'a published refusal names a code no registry declares').toEqual([]);
    expect([...reached].sort(), 'the codes the rows refuse with and the list the file publishes').toEqual(
      [...file.layout.codes].sort(),
    );
  });

  it('keeps the span-only case and the covered case distinguishable by their outcomes', () => {
    const met = vectorNamed('continuous-coverage-met');
    const span = vectorNamed('span-only-would-have-met-under-the-span-rule');
    expect(met.assessment.outcome).toBe('met');
    expect(met.assessment.coverage.result).toBe('covered');
    expect(span.assessment.outcome).toBe('indeterminate');
    expect(span.assessment.coverage.result).toBe('indeterminate');
    // The old span rule, as a script would have computed it: the distance between the two stamps against
    // the required period, with the newest head equal to the pinned head. It says met, and the reading does
    // not, which is the whole reason the two rows are published together.
    const scope = scopeOf(span.document);
    const spanBlock = coverageOf(span.document)['span'] as Block;
    const required = (scope['duty'] as Block)['requiredSeconds'];
    const pinned = ((scope['intake'] as Block)['expectedHead'] as Block)['sha256'];
    const oldRuleMet =
      Number(spanBlock['to']) - Number(spanBlock['from']) >= Number(required) && spanBlock['newestHead'] === pinned;
    expect(oldRuleMet, 'the span-only row is not a case the old span rule would have called met').toBe(true);
    expect(span.assessment.outcome, 'the span-only row reaches met under the new rule').not.toBe('met');
  });

  it('names in its document the counts its rows carry', () => {
    expect(
      countInBullet(/publishes ([0-9]+) assessment rows/u, 'the assessment rows'),
      'docs/vectors.md counts a different number of assessment rows than the file publishes',
    ).toBe(file.vectors.length);
    expect(
      countInBullet(/and ([0-9]+) refusals/u, 'the refusals'),
      'docs/vectors.md counts a different number of refusals than the file publishes',
    ).toBe(file.refusals.length);
  });
});
