import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  DISCLOSURE_DUTY_CITATIONS,
  DISCLOSURE_DUTY_POINTERS,
  DISCLOSURE_RECORD_LIMITS,
  ReceiptError,
  disclosureRecordBytes,
  extractMarkedRegion,
  fromBase64Url,
  parseDisclosureRecord,
  toBase64Url,
  toHex,
  type DisclosureRecord,
  type DisclosureTransformation,
} from '@ashaveri/receipt';
import { markedBuffered } from './marking-shapes.ts';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', 'data');
const SCRIPTS = dirname(fileURLToPath(import.meta.url));

/**
 * The recorded run of the completion through applications outside this repository, written by
 * `disclosure-content-path-capture.ts`. It is read rather than re-run here because the applications that
 * produced it belong to a machine and a version each, while these vectors have to come out of a
 * regeneration the same way wherever it is run.
 */
const OBSERVATION = join(SCRIPTS, 'disclosure-content-path-observation.json');

interface ObservedStage {
  readonly name: string;
  readonly application: string;
  readonly applicationVersion: string;
  readonly note: string;
  readonly outputBase64Url?: string;
}

interface Observation {
  readonly start: string;
  readonly startBase64Url: string;
  readonly stages: readonly ObservedStage[];
}

function recordedRun(): Observation {
  if (!existsSync(OBSERVATION)) {
    throw new Error(
      'disclosure-content-path-observation.json is not beside this script, and an outcome for a real application step is read off the bytes that step produced rather than stated without them',
    );
  }
  const recorded = JSON.parse(readFileSync(OBSERVATION, 'utf8')) as Observation;
  if (toHex(sha256(fromBase64Url(recorded.startBase64Url))) !== toHex(sha256(RESPONSE))) {
    throw new Error('the recorded real content path does not start from the response these vectors publish');
  }
  return recorded;
}

/**
 * One stage of the recorded run, with the outcome the published rule gives over the bytes the application
 * wrote. A stage that published no bytes is a step that did not run, and it is published without an
 * outcome: the rule was never handed anything to locate, so there is nothing here for it to have said.
 */
function realStage(one: ObservedStage): Record<string, unknown> {
  const bytes = one.outputBase64Url === undefined ? undefined : fromBase64Url(one.outputBase64Url);
  return {
    name: one.name,
    application: one.application,
    applicationVersion: one.applicationVersion,
    outcome: bytes === undefined ? 'untested' : outcomeThrough(bytes),
    ...(bytes === undefined ? {} : { outputBase64Url: one.outputBase64Url, outputSha256: toHex(sha256(bytes)) }),
    note: one.note,
  };
}

const encoded = (text: string): Uint8Array => new TextEncoder().encode(text);
const decoded = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

/**
 * The transformation harness: one content path, run through its copying, rendering and export
 * transformations, with the mark's detectability measured through each by the published extraction
 * rule rather than asserted beside it.
 *
 * The content path is the buffered marked completion this package publishes as
 * `marking-v1.json#buffered-member`, built by the same builder that suite signs its rows from. What the
 * harness measures is what the rule locates after each transformation: one region is `detectable`, no
 * single region is `not-detectable`, and a transformation the harness does not implement is recorded as
 * `untested` rather than omitted, because a list of only the transformations that worked is a claim about
 * a path nobody tested whole.
 *
 * The harness can only measure what it implements, which is a reshuffling of these bytes. The other half
 * of the question, what the mark does in the applications a customer actually copies, renders and exports
 * the completion through, is recorded beside it: `disclosure-content-path-capture.ts` runs the same
 * response through them and writes what each produced, and this file states an outcome for a stage of
 * that path only over the bytes the stage published, so a step that did not run is a step recorded
 * without a verdict. Both halves keep detectability and digest agreement apart: a re-serialization keeps
 * the member findable while spelling its bytes differently, so the region is still detected and the
 * receipt's `mk.d` no longer matches it. The family's note keeps the two questions apart too.
 */

const MARKED = markedBuffered();
const RESPONSE = encoded(MARKED.response);

/** The completion's displayed text, which is what a render or a plain-text export carries. */
function contentOf(bytes: Uint8Array): string {
  const body = JSON.parse(decoded(bytes)) as { choices: Array<{ message: { content: string } }> };
  return body.choices[0]!.message.content;
}

type Transformation = (bytes: Uint8Array) => Uint8Array;

/** The transformations this harness implements, each one way a content path moves its bytes. */
const IMPLEMENTED: Readonly<Record<string, Transformation>> = {
  'byte-copy': (bytes) => bytes.slice(),
  'json-reparse': (bytes) => encoded(JSON.stringify(JSON.parse(decoded(bytes)))),
  'text-render': (bytes) => encoded(contentOf(bytes)),
  'plain-text-export': (bytes) => encoded(`${contentOf(bytes)}\n`),
};

/** The transformations named and not run: the harness implements no pixel or audio rendering. */
const UNTESTED: readonly string[] = ['pixel-render', 'audio-render'];

function outcomeThrough(bytes: Uint8Array): 'detectable' | 'not-detectable' {
  try {
    extractMarkedRegion('provenance-v1', bytes);
    return 'detectable';
  } catch {
    return 'not-detectable';
  }
}

const MEASURED: readonly DisclosureTransformation[] = [
  ...Object.entries(IMPLEMENTED).map(([name, run]): DisclosureTransformation => ({
    name,
    outcome: outcomeThrough(run(RESPONSE)),
  })),
  ...UNTESTED.map((name): DisclosureTransformation => ({ name, outcome: 'untested' })),
];

const REGION_RECORD: DisclosureRecord = {
  v: 1,
  obligor: 'the deployer serving the completion',
  duty: 'ai-act-50-4',
  scheme: 'provenance-v1',
  served: { kind: 'region', sha256: toHex(sha256(encoded(MARKED.region))) },
  transformations: MEASURED,
  limits: DISCLOSURE_RECORD_LIMITS,
};

const TEXT_RECORD: DisclosureRecord = {
  ...REGION_RECORD,
  duty: 'ai-act-50-5',
  served: { kind: 'text', text: 'This response was generated by an AI system.' },
};

/**
 * One edit to the writer's own bytes, every other byte left as the writer wrote it, which is how the
 * refusal rows are made: the writer refuses a malformed record, so a refusal row cannot come from it
 * directly, and a row assembled out of junk would test nothing. The writer's format is
 * `JSON.stringify` at two spaces with a trailing newline, so parsing that text, moving one position
 * and writing it back in the same format reproduces the writer's bytes everywhere except the edit.
 */
function editedRecord(base: DisclosureRecord, mutate: (document: Record<string, unknown>) => void): Uint8Array {
  const document = JSON.parse(decoded(disclosureRecordBytes(base))) as Record<string, unknown>;
  mutate(document);
  return encoded(`${JSON.stringify(document, null, 2)}\n`);
}

interface Row {
  readonly name: string;
  readonly note: string;
  readonly expected: string;
  readonly bytes: Uint8Array;
  readonly fault?: { readonly at: string; readonly states: string };
}

const ROWS: readonly Row[] = [
  {
    name: 'record-marked-region-v1',
    note: 'A record naming the marked region by the digest mk.d carries, beside the transformation set the harness measured over the published buffered completion. The region arm is the record stating which span of the response the notice travels with, and the digest is checkable against the response bytes the rule block publishes.',
    expected: 'verify-ok',
    bytes: disclosureRecordBytes(REGION_RECORD),
  },
  {
    name: 'record-notice-text-v1',
    note: 'A record stating the notice text served to a reader, under the first-exposure pointer, beside the same measured transformation set. The text arm is the disclosure a human reads; the mark it travels beside is named by the scheme member, and the two are one record\'s two statements rather than two records.',
    expected: 'verify-ok',
    bytes: disclosureRecordBytes(TEXT_RECORD),
  },
  {
    name: 'record-unknown-duty-v1',
    note: 'A well-formed record whose duty names a provision outside the pointer registry: the document is whole and it is the provision it names that this reader has no pointer for, which is the refusal DISCLOSURE_RECORD_UNKNOWN_DUTY exists for, apart from a malformed document.',
    expected: 'DISCLOSURE_RECORD_UNKNOWN_DUTY',
    bytes: editedRecord(REGION_RECORD, (document) => {
      document['duty'] = 'ai-act-50-2';
    }),
    fault: { at: 'duty', states: 'a label the pointer registry does not hold' },
  },
  {
    name: 'record-unknown-scheme-v1',
    note: 'A well-formed record whose scheme names a marking label outside the registry mk.sch reads. The answer is the marking registry\'s own code, UNSUPPORTED_SCHEME, because one registry owns one code wherever its labels arrive, and the detail names the record position.',
    expected: 'UNSUPPORTED_SCHEME',
    bytes: editedRecord(REGION_RECORD, (document) => {
      document['scheme'] = 'provenance-v2';
    }),
    fault: { at: 'scheme', states: 'a label the marking registry does not hold' },
  },
  {
    name: 'record-limits-withheld-v1',
    note: 'A record leaving out the limits member, which the layout requires and whose text is the format\'s own sentence. A record stating no limits is a silence a reader would have to guess at, and a record wording its own limits is refused the same way: the limits are not the writer\'s to word.',
    expected: 'DISCLOSURE_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(REGION_RECORD, (document) => {
      delete document['limits'];
    }),
    fault: { at: 'limits', states: 'the member the layout requires and these bytes leave out' },
  },
  {
    name: 'record-region-under-none-v1',
    note: 'A record naming a served region beside a scheme that declares no region of the response is marked: the document contradicting itself about whether a region exists, which is a malformed record rather than a verdict about the deployment.',
    expected: 'DISCLOSURE_RECORD_BAD_DOCUMENT',
    bytes: editedRecord(REGION_RECORD, (document) => {
      document['scheme'] = 'none';
    }),
    fault: { at: 'served', states: 'a region served beside a scheme that declares no region' },
  },
];

/** What the shipped reader answers for each row, so the file cannot lie about itself. */
function verdictOf(bytes: Uint8Array): string {
  try {
    parseDisclosureRecord(bytes);
    return 'verify-ok';
  } catch (err) {
    if (err instanceof ReceiptError) return err.code;
    throw err;
  }
}

function main(): void {
  const run = recordedRun();

  for (const one of ROWS) {
    const observed = verdictOf(one.bytes);
    if (observed !== one.expected) {
      throw new Error(`${one.name}: the reader answers ${observed}, not the ${one.expected} this row states`);
    }
  }

  const vectors = ROWS.map((one) => ({
    name: one.name,
    note: one.note,
    expected: one.expected,
    recordBase64Url: toBase64Url(one.bytes),
    recordByteLength: one.bytes.length,
    ...(one.fault === undefined ? {} : { fault: one.fault }),
  }));

  writeFileSync(
    join(DATA, 'disclosure-record-v1.json'),
    JSON.stringify(
      {
        version: 1,
        description:
          'The disclosure record beside the marking region: who owed the notice, the duty pointer it answers, the text or region served, and the transformation set it was tested through, with unsupported transformations recorded rather than omitted. The content path these records state is the buffered completion this suite publishes, and the outcomes in them are measured through the published extraction rule over the transformations this harness implements. The block rule.realContentPath records the same completion put through one browser and read back out of the archive it exported, stage by stage with the application and version that ran each, and a step the run could not reach is recorded without an outcome. No row carries a claim about what an application does to the mark that its published bytes do not support. Each row carries the record bytes the shipped writer made, or one edit of them at the position its fault names, and the verdict the shipped reader owes those bytes.',
        rule: {
          registry: 'docs/receipt-spec.md section 3.3',
          reader: 'parseDisclosureRecord in @ashaveri/receipt',
          writer: 'disclosureRecordBytes in @ashaveri/receipt',
          dutyPointers: [...DISCLOSURE_DUTY_POINTERS],
          dutyCitations: { ...DISCLOSURE_DUTY_CITATIONS },
          limits: DISCLOSURE_RECORD_LIMITS,
          contentPath: {
            response: 'marking-v1.json#buffered-member',
            responseBase64Url: toBase64Url(RESPONSE),
            note: 'The fixture content path the harness ran over, byte for byte the response the marking suite publishes for the buffered shape. No row above stands in for an application\'s own path, and the applications that ran one are recorded in rule.realContentPath.',
          },
          realContentPath: {
            start: run.start,
            startBase64Url: toBase64Url(RESPONSE),
            recordedBy: 'packages/fixtures/scripts/disclosure-content-path-capture.ts',
            note: 'The same completion carried through the applications a customer copies, renders and exports it with, in one recorded run of them rather than a harness of this package. Each stage names the application and the version that wrote its bytes and states what the published extraction rule locates in them, so the verdict beside a stage is a reading of the artifact and not a word beside a name. A stage with no bytes is a step the run could not reach: it names the application and records the silence, and states no outcome.',
            stages: run.stages.map(realStage),
          },
          transformations: [
            ...Object.keys(IMPLEMENTED).map((name) => ({
              name,
              implemented: true,
              note: 'Run by the harness; the outcome is what extractMarkedRegion locates after the transformation, which is the region\'s survival and not the digest\'s agreement.',
            })),
            ...UNTESTED.map((name) => ({
              name,
              implemented: false,
              note: 'Named and recorded as untested: the harness implements no pixel or audio rendering, and a JSON transcript region is not a pixel or audio watermark.',
            })),
          ],
          encodings: 'byte strings unpadded base64url, digests lowercase hex',
        },
        vectors,
      },
      null,
      2,
    ) + '\n',
  );

  for (const one of vectors) console.log(`${one.name}: ${one.expected}`);
}

main();