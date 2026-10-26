import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RECEIPT_ID_CHARS } from '../access.js';
import { daysToSeconds } from '../duty-window.js';
import { intakeGuardRefusal, type IntakeGuardFigures } from '../server.js';
import {
  HOST_CLOCK_SOURCE,
  openFileReceiptStore,
  openMemoryReceiptStore,
  receiptsNeededForWindow,
  RECEIPT_STORE_FILE,
  type ReceiptRetention,
  type ReceiptStore,
  type RetainedWindow,
} from '../store.js';

/**
 * What a five-year receipts window costs at the traffic one address is held to, and what this code
 * answers when a volume cannot hold it.
 *
 * Run it as `pnpm measure:five-year-window` from the workspace root, which builds first: every figure
 * below comes out of the compiled store, the compiled guard and the compiled day-to-second conversion,
 * so a re-typed copy of the arithmetic cannot quietly become the thing being measured.
 *
 * Section 1 of `docs/access-control.md` states a connection's bound as 6,000 requests a minute and
 * reads that as a hundred requests a second sustained. A receipt is filed for every admitted
 * completion, so a deployment carrying that traffic from one address files a hundred receipts a second,
 * and the faster a deployment is, the sooner the same window asks for more. `--receipts-days` is the
 * flag that sets the period, and five years of whole days is 1826 of them.
 *
 * The questions this answers, in the order it prints them: how many receipts a durability bound would
 * have to hold for that pairing, how many bytes that is at the width one of this store's own records
 * has, what the widest bound a receipt file can state actually is, and what the opening and the
 * admission guard say when the bound falls short of the period beside it.
 *
 * Nothing here is timed, and no figure below is a duration. A machine that appends more slowly is not a
 * machine that needs fewer receipts, and any host's per-turn loop floor turns a wall-clock figure into
 * a floor rather than a cost. Every quantity here is arithmetic over counts, stamps and byte widths,
 * and the refusals are strings the code produced.
 *
 * The receipts are filed in a temporary directory outside the repository and removed on the way out.
 * Nothing here writes inside the repository.
 */

/** Five years of whole days, leap day included: the shortest spelling the period flag can state. */
const FIVE_YEAR_DAYS = 1826;
/** The rate `docs/access-control.md` states for one address, in requests, and so receipts, a second. */
const ADDRESS_RATE = 100;
/** The durability bound `gateway/src/cli.ts` opens a volume with when an operator names no count. */
const SHIPPED_BOUND = 10_000;
/** The payload width of the record `packages/fixtures/data/chain-v1.json` publishes its framing with. */
const VECTOR_PAYLOAD_BYTES = 64;
/**
 * A receipt this repository signed, held as a published image. Its width is taken from the bytes rather
 * than from a number this script could have typed: a store record is only as large as the receipt the
 * gateway put inside it, and the vector's 64 byte payload is a fixture, not a completion.
 */
const ISSUED_RECEIPT_IMAGE = new URL(
  '../../../packages/fixtures/data/receipts/receipt-buffered-v1.cbor',
  import.meta.url,
);
/** The period, taken through the one place this repository turns days into the store's seconds. */
const PERIOD_SECONDS = daysToSeconds(FIVE_YEAR_DAYS);

const GIB = 1024 ** 3;

/** One 48 character id, the width `ReceiptNamespace.mint` produces for a completion. */
function mintedId(index: number): string {
  return Array.from(new Uint8Array(createHash('sha256').update(`window ${String(index)}`).digest()))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, RECEIPT_ID_CHARS);
}

/** A retained set that measures `ADDRESS_RATE` receipts a second across `seconds` of its own stamps. */
function atRate(seconds: number): RetainedWindow {
  return { from: 0, to: seconds, count: ADDRESS_RATE * seconds + 1 };
}

/** The retained set of the same rate arriving as a burst inside one instant, which the store floors to one second. */
function burstAtRate(): RetainedWindow {
  return { from: 0, to: 0, count: ADDRESS_RATE + 1 };
}

function heading(text: string): void {
  console.log(`\n${text}`);
  console.log('-'.repeat(text.length));
}

/**
 * How many bytes the store's own writer puts on the volume for one record of a minted id and this
 * payload, and how many of them the framing holds whatever the payload is.
 */
async function recordWidths(payloadBytes: number): Promise<{ record: number; framing: number }> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-window-'));
  try {
    const store = await openFileReceiptStore({ dir });
    const instant = HOST_CLOCK_SOURCE.nowSeconds();
    await store.put(mintedId(0), new Uint8Array(0), instant);
    const bare = (await stat(join(dir, RECEIPT_STORE_FILE))).size;
    await store.put(mintedId(1), new Uint8Array(payloadBytes), instant);
    const filled = (await stat(join(dir, RECEIPT_STORE_FILE))).size;
    return { record: filled - bare, framing: bare - RECEIPT_ID_CHARS };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/**
 * The widest durability bound a trim record can state: the largest value the 4 byte field it files a
 * bound in carries. Nothing here invents it, and the store refuses a configured bound above it.
 */
const WIDEST_STATABLE_BOUND = 4_294_967_295;
/**
 * What the store answers a configured durability bound, and what the file then states about it.
 *
 * `--receipts-keep` parses every positive whole number, so the question is what the record does with it.
 * A trim record files the bound a prefix retired under in 4 bytes, and the store refuses a bound wider
 * than that rather than filing the field's ceiling in its place, so this prints either the number the
 * record states or the refusal the door gave. The two calls below meet both halves of that rule.
 */
async function boundTheFileStates(configuration: number): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-window-'));
  try {
    const retention: ReceiptRetention = { maxAgeSeconds: 10, maxCount: configuration, time: HOST_CLOCK_SOURCE };
    const instant = HOST_CLOCK_SOURCE.nowSeconds();
    let opened: ReceiptStore | null = null;
    let refusal = '';
    try {
      opened = await openFileReceiptStore({ dir, retention });
    } catch (error) {
      refusal = error instanceof Error ? error.message : String(error);
    }
    if (opened === null) {
      return `refused before a byte was written: ${refusal}`;
    }
    // Two records, the first one already older than the age bound by the time the second lands, so a
    // prefix retires and the file has to state the policy it retired under.
    await opened.put(mintedId(0), new Uint8Array(VECTOR_PAYLOAD_BYTES), instant - 30);
    await opened.put(mintedId(1), new Uint8Array(VECTOR_PAYLOAD_BYTES), instant - 20);
    const trims = (await opened.chainState()).retired.trims;
    const last = trims.at(-1);
    if (last === undefined) {
      throw new Error('no retirement wrote a trim record, so the bound it retired under was never stated');
    }
    const stated = last.under.maxCount;
    if (stated === undefined) {
      throw new Error('the trim record stated no durability bound, which is how a missing cap is written');
    }
    return `opens, and the trim record states ${String(stated)} receipts`;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/**
 * The longest whole-day period the given durability bound can hold at the rate one address is held to.
 *
 * Found by asking the store's own function one more day at a time rather than by solving it here, so
 * the answer is whatever the arithmetic the refusals use says it is, rounding and all.
 */
function longestHeldDays(bound: number, held: RetainedWindow): number {
  let days = 0;
  for (;;) {
    const needed = receiptsNeededForWindow(daysToSeconds(days + 1), held);
    if (needed === null || needed > bound) break;
    days += 1;
  }
  return days;
}

/** The line a store prints when the period beside its durability bound cannot be held. */
async function openingRefusal(retention: ReceiptRetention, receipts: number): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ashaveri-window-'));
  try {
    const instant = HOST_CLOCK_SOURCE.nowSeconds();
    const written = await openFileReceiptStore({ dir });
    for (let index = 0; index < receipts; index++) {
      await written.put(mintedId(index), new Uint8Array(VECTOR_PAYLOAD_BYTES), instant);
    }
    await openFileReceiptStore({ dir, retention });
    return 'opened: the bound held the period at the traffic on the file';
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** The figures the admission guard carries for a store whose retained set measures that rate. */
async function guardFigures(retention: ReceiptRetention, receipts: number): Promise<IntakeGuardFigures | null> {
  const instant = HOST_CLOCK_SOURCE.nowSeconds();
  const store = openMemoryReceiptStore({ retention });
  for (let index = 0; index < receipts; index++) {
    await store.put(mintedId(index), new Uint8Array(VECTOR_PAYLOAD_BYTES), instant);
  }
  return intakeGuardRefusal({ retention }, await store.window());
}

const smallestBoundAtRate = ADDRESS_RATE + 1;
const fiveYears: ReceiptRetention = {
  maxAgeSeconds: PERIOD_SECONDS,
  maxCount: smallestBoundAtRate,
  time: HOST_CLOCK_SOURCE,
};

heading('The pairing');
console.log(`period flag:            --receipts-days ${String(FIVE_YEAR_DAYS)}`);
console.log(`period as the store reads it: ${String(PERIOD_SECONDS)} seconds`);
console.log(`rate:                   ${String(ADDRESS_RATE)} receipts a second, one address's sustained allowance`);
console.log(`durability bound:       ${String(SHIPPED_BOUND)} receipts, the count this CLI ships`);

heading('The receipts the durability bound would have to hold');
const neededAtRate = receiptsNeededForWindow(PERIOD_SECONDS, atRate(100));
const neededAtBurst = receiptsNeededForWindow(PERIOD_SECONDS, burstAtRate());
const neededAtShippedBound = receiptsNeededForWindow(PERIOD_SECONDS, { from: 0, to: 99, count: SHIPPED_BOUND });
console.log(`spread over its own hundred seconds: ${String(neededAtRate)} receipts`);
console.log(`arriving as one burst inside an instant: ${String(neededAtBurst)} receipts`);
console.log(`at the shipped bound, which that traffic reaches after a hundred seconds: ${String(neededAtShippedBound)} receipts`);
console.log(`which is ${String(Math.round((neededAtShippedBound ?? 0) / SHIPPED_BOUND))} times the bound this CLI ships`);

heading("The bytes that is, at the width one of this store's records has");
const issuedReceipt = await readFile(ISSUED_RECEIPT_IMAGE);
const widths = await recordWidths(VECTOR_PAYLOAD_BYTES);
const wide = await recordWidths(issuedReceipt.length);
console.log(`framing the store adds to every record: ${String(widths.framing)} bytes`);
console.log(`id a gateway mints:                     ${String(RECEIPT_ID_CHARS)} bytes`);
console.log(
  `one record of a ${String(VECTOR_PAYLOAD_BYTES)} byte receipt:           ${String(widths.record)} bytes, ` +
    'the width the published chain vector has',
);
console.log(
  `one record of a ${String(issuedReceipt.length)} byte receipt:          ${String(wide.record)} bytes, ` +
    'the width of a receipt this repository signed',
);
const atVectorWidth = neededAtRate === null ? 0n : BigInt(neededAtRate) * BigInt(widths.record);
const atIssuedWidth = neededAtRate === null ? 0n : BigInt(neededAtRate) * BigInt(wide.record);
console.log(
  `the window at ${String(widths.record)} bytes a receipt:  ${atVectorWidth.toString()} bytes, ` +
    `about ${(atVectorWidth / BigInt(GIB)).toString()} GiB`,
);
console.log(
  `the window at ${String(wide.record)} bytes a receipt:  ${atIssuedWidth.toString()} bytes, ` +
    `about ${(atIssuedWidth / BigInt(GIB)).toString()} GiB`,
);
console.log(
  `every further byte a deployment signs into a receipt costs ${String(neededAtRate ?? 0)} ` +
    'more bytes on that volume',
);

heading('What a receipt file states about a durability bound');
const configuration = neededAtRate ?? 0;
const atNeed = await boundTheFileStates(configuration);
const atCeiling = await boundTheFileStates(WIDEST_STATABLE_BOUND);
console.log(`a start configured with:        --receipts-keep ${configuration.toLocaleString('en-US')}`);
console.log(`the store's answer there:       ${atNeed}`);
console.log(`a start at the field's ceiling: --receipts-keep ${String(WIDEST_STATABLE_BOUND)}`);
console.log(`the store's answer there:       ${atCeiling}`);
const heldDays = longestHeldDays(WIDEST_STATABLE_BOUND, atRate(100));
console.log(`the widest bound states a window of: ${String(heldDays)} days at that rate`);
console.log(`the five-year window asks for:       ${String(FIVE_YEAR_DAYS)} days`);

heading('What the two readings print');
console.log(`opening: ${await openingRefusal(fiveYears, smallestBoundAtRate)}`);
const figures = await guardFigures(fiveYears, smallestBoundAtRate);
if (figures === null) {
  console.log('guard: silent, which is a defect in this script rather than in the store');
} else {
  console.log(
    'guard: 429 RECEIPT_WINDOW_UNHOLDABLE, with retained ' +
      `${String(figures.retained)} of a bound of ${String(figures.bound)}, stamps spanning ` +
      `${String(figures.spanSeconds)} seconds of which ${String(figures.spanSupportSeconds)} support a rate, ` +
      `read from ${figures.source}, against a period of ${String(figures.periodSeconds)} seconds that takes ` +
      `${String(figures.needed)} receipts, ${String(figures.needed - figures.bound)} more than the bound holds`,
  );
}

heading('What the figures answer');
console.log(
  `A five-year window at one address's sustained allowance asks a volume for ${String(configuration)} ` +
    `receipts, which is ${atVectorWidth.toString()} bytes of one file at the narrowest record this format ` +
    `writes and ${atIssuedWidth.toString()} bytes at the width of a receipt this repository has published.`,
);
console.log(
  `The widest durability bound a trim record states is ${String(WIDEST_STATABLE_BOUND)} receipts, and that ` +
    `holds ${String(heldDays)} days at this rate. ${String(FIVE_YEAR_DAYS)} days is past it, and so is the ` +
    'count this window needs, which the store refuses to open on rather than filing as the ceiling: no ' +
    'setting of --receipts-keep closes this window on one flat file. What that ceiling does not limit is ' +
    "the volume, because the sidecar index files a record's position, sequence and stamp in 8 byte fields; " +
    'the limit is on what a trim record can state about a policy, not on how many receipts a file carries.',
);
console.log(
  'What the code does with that pairing is refuse it three times: before a byte is written when a configured ' +
    'bound is wider than the record that files it can state, at the opening when a bound and a period cannot ' +
    'be honoured at the traffic on the file, and at every completion while the store sits at that bound. Each ' +
    'sentence carries the count it derived rather than an opinion about capacity. Nothing here chooses what ' +
    'a deployment does next: a window this length at this traffic is a question about how much one file ' +
    'keeps, and the answer the repository gives is the refusal above.',
);
