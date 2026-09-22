import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import { cddlRule, memberDeclarations, required } from './cddl.js';
import {
  decodeReceipt,
  issueReceipt,
  signingKeyFromSeed,
  type ReceiptPayload,
} from '../src/index.js';

/**
 * The pack's per-item provenance, run as a walk.
 *
 * `pack.cddl` states one claim that is not a member list: that the four values `PackItem` declares are
 * the whole of what it takes to rebuild the record the store hashed, and so to walk a span from the
 * anchor the manifest signs to the head it signs. That is a claim about bytes, so it is checked
 * against bytes — ones this file generates with the package's own codec, from a signing key with a
 * fixed seed, because a frame pasted in here would be a frame nobody could re-derive.
 *
 * The four positions are read out of the CDDL and given their jobs by the types the format writes:
 * the text is the id the record names, the integer is the stamp it was chained at, the 32-byte string
 * is the predecessor's digest, and the nested CBOR is the receipt itself. A fifth position of any of
 * those shapes stops the run rather than being ignored, because a member that reaches this format
 * without a job here is a member no reader was told what to do with.
 *
 * The framing itself is the store's, published in section 5.2 of the specification and as byte images
 * in `packages/fixtures/data/chain-v1.json`, and it is tested against those images where they live.
 * What lives here is the converse question, which is the one a format has to answer: whether a reader
 * holding nothing but what `PackItem` carries can rebuild a frame at all.
 *
 * The second half of what lives here is the reader those frames are rebuilt for. A span bounds the
 * stamps inside it, the window has to have closed before the reads that filled it, and the retention
 * figure the manifest signs has to be at least the age of the oldest receipt the manifest carries: no
 * link sees any of that, so `readSpan` below applies the rules the way a reader applies them and names
 * the rule it applied, because a reader that reported all of them as one broken chain would be the
 * confusion the container exists to keep decidable.
 */
const packCddlPath = fileURLToPath(new URL('../pack.cddl', import.meta.url));

/** Which position of `PackItem` plays which part of a record, read off the format's type expressions. */
function itemPositions(cddl: string): { id: string; stamp: string; predecessor: string; payload: string } {
  if (!cddl.includes('PackItem = {')) throw new Error(`PackItem is not declared in ${packCddlPath}`);
  const roles: Array<'id' | 'stamp' | 'predecessor' | 'payload'> = [];
  const names: string[] = [];
  for (const member of memberDeclarations(cddlRule(cddl, 'PackItem'))) {
    const role =
      member.type === 'int' ? 'stamp'
        : member.type === 'bstr .size 32' ? 'predecessor'
          : /^bstr \.cbor [A-Z]/u.test(member.type) ? 'payload'
            : /^tstr(?: \.size \(\d+\.\.\d+\))?$/u.test(member.type) ? 'id'
              : undefined;
    if (role === undefined) {
      throw new Error(`PackItem declares ${member.name} as "${member.type}", which this walk gives no job`);
    }
    if (roles.includes(role)) {
      throw new Error(`PackItem declares two ${role} positions, ${names[roles.indexOf(role)]} and ${member.name}`);
    }
    roles.push(role);
    names.push(member.name);
  }
  const out: Record<string, string> = {};
  roles.forEach((role, index) => {
    out[role] = names[index]!;
  });
  for (const role of ['id', 'stamp', 'predecessor', 'payload'] as const) {
    required(out[role], `PackItem declares no ${role} position, so a reader cannot rebuild a frame from it`);
  }
  return out as { id: string; stamp: string; predecessor: string; payload: string };
}

const POSITIONS = itemPositions(readFileSync(packCddlPath, 'utf8'));

/** One receipt, and the three values a record was hashed with, as a reader receives them. */
interface Item {
  readonly id: string;
  readonly stamp: number;
  readonly predecessor: Uint8Array;
  readonly payload: Uint8Array;
}

const ZERO32 = new Uint8Array(32);
const encoder = new TextEncoder();

/** `Record = len:u32 || kind:u8 || prev:32 || iat:u64 || idLen:u16 || id || payload || digest:32`. */
function digestInput(item: Item): Uint8Array {
  const id = encoder.encode(item.id);
  const bytes = new Uint8Array(1 + 32 + 8 + 2 + id.length + item.payload.length);
  const view = new DataView(bytes.buffer);
  let at = 0;
  bytes[at] = 0; // kind: a receipt record, the only kind a pack item ever is
  at += 1;
  bytes.set(item.predecessor, at);
  at += 32;
  view.setBigUint64(at, BigInt(item.stamp));
  at += 8;
  view.setUint16(at, id.length);
  at += 2;
  bytes.set(id, at);
  at += id.length;
  bytes.set(item.payload, at);
  return bytes;
}

function recordDigest(item: Item): Uint8Array {
  return sha256(digestInput(item));
}

/** The payload a receipt attests, with only the two positions the pack reads moving per case. */
function samplePayload(iat: number, nonce: number): ReceiptPayload {
  const digest = sha256(new Uint8Array([nonce]));
  return {
    v: 1,
    iss: 'ashaveri-pack-walk',
    ins: 'cvm-pack-1',
    iat,
    nce: new Uint8Array(16).fill(nonce),
    req: digest,
    res: digest,
    mdl: 'mock-model-1',
    wts: digest,
    meas: { tee: 'software', m: digest },
    att: { d: digest, ts: iat - 60, url: 'https://inference.ashaveri.com/v1/attestation' },
    epk: 0,
    tok: { p: 1, c: 1 },
  };
}

const KEY = signingKeyFromSeed(new Uint8Array(32).fill(7));
const BASE = 1_772_000_000;

/** What goes into a chained span: the id the record names, the stamp it was chained at, and a nonce. */
interface Entry {
  readonly id: string;
  readonly stamp: number;
  readonly nonce: number;
}

/** The three receipts every case below starts from, one second apart as the store chains them. */
const SPAN: readonly Entry[] = [
  { id: 'receipt-0', stamp: BASE, nonce: 1 },
  { id: 'receipt-1', stamp: BASE + 1, nonce: 2 },
  { id: 'receipt-2', stamp: BASE + 2, nonce: 3 },
];

/** Three receipts from the package's own codec, chained in the order given from an empty anchor. */
function chained(entries: Iterable<Entry>): { items: Item[]; anchor: Uint8Array; head: Uint8Array } {
  const items: Item[] = [];
  let head: Uint8Array = ZERO32;
  for (const entry of entries) {
    const item: Item = {
      id: entry.id,
      stamp: entry.stamp,
      predecessor: head,
      payload: issueReceipt(samplePayload(entry.stamp, entry.nonce), KEY),
    };
    items.push(item);
    head = recordDigest(item);
  }
  return { items, anchor: ZERO32, head };
}

/** The three-receipt span every case below starts from, issued and chained in order. */
function issued(): { items: Item[]; anchor: Uint8Array; head: Uint8Array } {
  return chained(SPAN);
}

/**
 * The walk a reader runs: start at the item whose predecessor is the anchor, and follow the digests
 * until the head. Nothing here is told the order, which is the point of the exercise, and every step
 * recomputes a digest from what the item carries rather than trusting the value the next one names.
 */
function walk(items: readonly Item[], anchor: Uint8Array, head: Uint8Array): Item[] {
  const seen = new Set<string>();
  const ordered: Item[] = [];
  let cursor = anchor;
  for (;;) {
    const next = items.find((item) => !seen.has(item.id) && sameBytes(item.predecessor, cursor));
    if (next === undefined) break;
    seen.add(next.id);
    ordered.push(next);
    cursor = recordDigest(next);
  }
  const last = ordered[ordered.length - 1];
  if (last === undefined || !sameBytes(cursor, head)) {
    throw new Error(`the walk reached ${ordered.length} item(s) and stopped at a digest that is not the head`);
  }
  return ordered;
}

/** The manifest's statements about a span of items, beyond the two endpoints a walk runs between. */
interface Claim {
  readonly anchor: Uint8Array;
  readonly head: Uint8Array;
  readonly from: number;
  readonly to: number;
  readonly at: number;
  readonly held: number;
  readonly required: number;
  readonly rev: number;
}

/**
 * The span, the assembly instant and the retention figure these items would have earned, with any of
 * them overridden by the case that wants one moved. Every fact starts out consistent with the items, so
 * a refusal below can only have arrived for the one relation the case broke.
 */
function claimFor(
  items: readonly Item[],
  anchor: Uint8Array,
  head: Uint8Array,
  over: Partial<Claim> = {},
): Claim {
  const stamps = items.map((item) => item.stamp);
  const oldest = Math.min(...stamps);
  const to = Math.max(...stamps) + 1;
  return { anchor, head, from: oldest - 60, to, at: to, held: to - oldest, required: 3_600, rev: to - 30, ...over };
}

/**
 * The rules a reader applies to a span that the links between its items cannot see, in the order they
 * bite: no figure below zero, the window had closed before the reads began and the mapping the period
 * came from predates them, every stamp lies inside the window, each item is chained under the stamp its
 * own receipt attests, and the retention figure is at least the age of the oldest receipt the container
 * carries. Each refusal names its own rule, for the reason the format states the rules separately.
 */
function readSpan(items: readonly Item[], claim: Claim): Item[] {
  const figures: Record<string, number> = {
    from: claim.from,
    to: claim.to,
    at: claim.at,
    held: claim.held,
    required: claim.required,
    rev: claim.rev,
  };
  const belowZero = Object.entries(figures).filter(([, value]) => value < 0);
  if (belowZero.length > 0) {
    const named = belowZero.map(([name, value]) => `${name} ${String(value)}`).join(', ');
    throw new Error(`the pack states a quantity below zero: ${named}`);
  }
  if (claim.at < claim.to) {
    throw new Error(`assembly began at ${claim.at}, before the span closed at ${claim.to}`);
  }
  if (claim.rev > claim.at) {
    throw new Error(`the mapping revision ${claim.rev} postdates the reads at ${claim.at}`);
  }
  const ordered = walk(items, claim.anchor, claim.head);
  for (const item of ordered) {
    if (item.stamp < claim.from || item.stamp >= claim.to) {
      throw new Error(`${item.id} is stamped ${item.stamp}, outside the span ${claim.from} to ${claim.to}`);
    }
    const attested = decodeReceipt(item.payload).payload.iat;
    if (attested !== item.stamp) {
      throw new Error(`${item.id} is chained under ${item.stamp} and its receipt attests ${attested}`);
    }
  }
  const oldest = Math.min(...ordered.map((item) => item.stamp));
  const floor = claim.at - oldest;
  if (claim.held < floor) {
    throw new Error(
      `the pack states ${claim.held} seconds held at ${claim.at} and carries a receipt stamped ${oldest}, ${floor} seconds old`,
    );
  }
  return ordered;
}

/** The one comparison the container refuses to make, left where the format leaves it. */
function meetsDuty(claim: Claim): boolean {
  return claim.held >= claim.required;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((each, index) => each === b[index]);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (each) => each.toString(16).padStart(2, '0')).join('');
}

describe('a pack item carries what the walk needs', () => {
  it('names four positions and no more', () => {
    expect(POSITIONS).toEqual({ id: 'id', stamp: 'iat', predecessor: 'prev', payload: 'receipt' });
  });

  it('walks an unordered span from the anchor to the head', () => {
    const { items, anchor, head } = issued();
    // Reversed, and rotated: neither the array order nor the file order is what the reader is relying
    // on, so a walk that finished at the head from either spelling is a walk driven by the links.
    expect(walk([...items].reverse(), anchor, head).map((item) => item.id)).toEqual(['receipt-0', 'receipt-1', 'receipt-2']);
    expect(walk([items[2]!, items[0]!, items[1]!], anchor, head).map((item) => item.id)).toEqual([
      'receipt-0',
      'receipt-1',
      'receipt-2',
    ]);
    expect(toHex(head)).toHaveLength(64);
  });

  it('refuses a span with a receipt lifted out of the middle', () => {
    const { items, anchor, head } = issued();
    const shortened = [items[0]!, items[2]!];
    expect(() => walk(shortened, anchor, head)).toThrow(/is not the head/);
    // And the same omission with the successor rewound to close the hole, which is the forgery the
    // signed head exists to defeat: the links are then perfect and the span is still wrong, because
    // what left is only visible against an endpoint the reader did not choose.
    const closed: Item[] = [items[0]!, { ...items[2]!, predecessor: recordDigest(items[0]!) }];
    const forgedHead = recordDigest(closed[1]!);
    expect(() => walk(closed, anchor, head)).toThrow(/is not the head/);
    expect(walk(closed, anchor, forgedHead).length).toBe(2);
  });

  it('refuses a receipt whose bytes were edited after it was chained', () => {
    const { items, anchor, head } = issued();
    const edited = items.map((item, index) =>
      index === 1 ? { ...item, payload: new Uint8Array(item.payload.map((each) => each ^ 0x01)) } : item,
    );
    // One bit of one receipt: the frame still states its own length and names the right predecessor,
    // so only the digest over its own bytes notices, which is what a reader computes.
    expect(() => walk(edited, anchor, head)).toThrow(/is not the head/);
    expect(toHex(recordDigest(edited[1]!))).not.toBe(toHex(recordDigest(items[1]!)));
  });

  it('refuses a receipt restamped into a window it was never issued in', () => {
    const { items, anchor, head } = issued();
    const restamped: Item = { ...items[1]!, stamp: items[1]!.stamp + 3_600 };
    const moved = [items[0]!, restamped, items[2]!];
    // A stamp is inside the hashed input, so moving one breaks the link the next record names and the
    // walk refuses the span outright.
    expect(() => walk(moved, anchor, head)).toThrow(/is not the head/);
    // A deployment that also repairs the links has a span that walks cleanly from an anchor to a head
    // it signs, which is exactly the case the signed endpoints cannot reach: it is the equality of the
    // record's stamp with the `iat` the receipt attests that gives it away, and that is why
    // `pack.cddl` states the equality as part of the walk rather than as a courtesy.
    const second = { ...restamped, predecessor: recordDigest(items[0]!) };
    const third = { ...items[2]!, predecessor: recordDigest(second) };
    const repaired = [items[0]!, second, third];
    expect(walk(repaired, anchor, recordDigest(third)).map((item) => item.id)).toEqual([
      'receipt-0',
      'receipt-1',
      'receipt-2',
    ]);
    const attested = repaired.map((item) => decodeReceipt(item.payload).payload.iat);
    expect(attested).toEqual([BASE, BASE + 1, BASE + 2]);
    expect(attested.map((each, index) => each === repaired[index]!.stamp)).toEqual([true, false, true]);
    // A reader holding the whole manifest refuses this span by name. The claim is built around the
    // moved stamp, so the window closed after every item inside it and the retention figure covers the
    // oldest: the equality is the only rule left for it to break, and the only one it breaks.
    expect(() => readSpan(repaired, claimFor(repaired, anchor, recordDigest(third)))).toThrow(/its receipt attests/);
    // And the control that says so: the same three stamps, each receipt issued under the one its record
    // was chained at, is a span the same reader accepts.
    const restampedForReal = chained([
      SPAN[0]!,
      { id: 'receipt-1', stamp: BASE + 3_601, nonce: 2 },
      SPAN[2]!,
    ]);
    expect(() =>
      readSpan(restampedForReal.items, claimFor(restampedForReal.items, restampedForReal.anchor, restampedForReal.head)),
    ).not.toThrow();
  });

  it('reproduces a frame the widths of the framing fix', () => {
    const { items } = issued();
    const first = items[0]!;
    const input = digestInput(first);
    // `len` covers kind through digest, and the digest is taken over kind through payload, so the two
    // spans differ by the 32 bytes of the digest and the frame differs from the hashed input by those
    // 32 plus the 4 bytes of `len`. A reader who hashed the whole frame, length prefix and digest
    // included, would recompute a value no record carries and refuse a file written correctly.
    const hashedLength = 1 + 32 + 8 + 2 + encoder.encode(first.id).length + first.payload.length;
    expect(input.length).toBe(hashedLength);
    expect(first.payload.length).toBeGreaterThan(60);
    const len = hashedLength + 32;
    const frame = 4 + len;
    expect(frame).toBe(hashedLength + 36);
    // The prefix and the digest are the only bytes outside the hashed input, and the frame's final 32
    // bytes are the digest of everything between them.
    expect(frame - 32 - input.length).toBe(4);
    expect(input[0]).toBe(0);
    expect(toHex(sha256(input))).toBe(toHex(recordDigest(first)));
  });
});

describe('the span a reader answers for', () => {
  it('refuses a stamp outside the span, at either end, that the links let walk cleanly', () => {
    // A stamp is inside the hashed input and a span is not, so these two mutants walk from anchor to
    // head with nothing broken: the only thing wrong with them is that the receipt sits in a window the
    // manifest says it does not sit in. `to` is excluded, so a receipt stamped exactly at it is the
    // next pack's and this one has no business carrying it.
    const late = chained([...SPAN.slice(0, 2), { id: 'receipt-2', stamp: BASE + 3, nonce: 3 }]);
    expect(walk(late.items, late.anchor, late.head).length).toBe(3);
    expect(() =>
      readSpan(late.items, claimFor(late.items, late.anchor, late.head, { to: BASE + 3, at: BASE + 3 })),
    ).toThrow(/outside the span/);
    const early = chained([{ id: 'receipt-0', stamp: BASE - 61, nonce: 1 }, ...SPAN.slice(1)]);
    expect(walk(early.items, early.anchor, early.head).length).toBe(3);
    expect(() =>
      readSpan(early.items, claimFor(early.items, early.anchor, early.head, { from: BASE - 60 })),
    ).toThrow(/outside the span/);
  });

  it('refuses a span that had not closed when the reads began', () => {
    const { items, anchor, head } = issued();
    // One second early and nothing else moves: every stamp still lies inside the window and the held
    // figure still covers the oldest receipt, so the pack's only fault is that it answered for a period
    // that was still receiving while it was being assembled.
    expect(() => readSpan(items, claimFor(items, anchor, head, { at: BASE + 1 }))).toThrow(/before the span closed/);
    expect(() => readSpan(items, claimFor(items, anchor, head, { at: BASE + 2 }))).toThrow(/before the span closed/);
    // The edge itself is allowed: reads beginning at the very instant the window closes are reads of a
    // closed window, which is what `at` stamped before them states.
    expect(() => readSpan(items, claimFor(items, anchor, head, { at: BASE + 3 }))).not.toThrow();
  });

  it('refuses a quantity below zero, which is a kind of number the format does not have', () => {
    const { items, anchor, head } = issued();
    // CDDL types all of these `int`, so nothing in the layout refuses them and the floor is a rule about
    // what the numbers mean: an end stamp before the epoch, a retention figure below zero.
    expect(() => readSpan(items, claimFor(items, anchor, head, { to: -1 }))).toThrow(/below zero/);
    expect(() => readSpan(items, claimFor(items, anchor, head, { held: -1 }))).toThrow(/below zero/);
    expect(() => readSpan(items, claimFor(items, anchor, head, { required: -1 }))).toThrow(/below zero/);
  });

  it('refuses a mapping revision that lands after the reads began', () => {
    const { items, anchor, head } = issued();
    // `rev` is what makes `required` readable in a later year, and a revision dated after the instant
    // the pack started looking is not the revision its own period came from.
    expect(() => readSpan(items, claimFor(items, anchor, head, { rev: BASE + 4 }))).toThrow(
      /postdates the reads/,
    );
    expect(() => readSpan(items, claimFor(items, anchor, head, { rev: BASE + 3 }))).not.toThrow();
  });

  it('refuses a held figure younger than the oldest receipt the pack carries', () => {
    const { items, anchor, head } = issued();
    // The oldest item is three seconds old at the assembly instant, so a pack claiming two seconds of
    // retention contradicts itself: a shorter figure than that is refused as a malformed document, and
    // the one case below shows a whole document whose duty simply is not met.
    expect(() => readSpan(items, claimFor(items, anchor, head, { held: 2 }))).toThrow(/seconds held/);
    expect(() => readSpan(items, claimFor(items, anchor, head, { held: 3 }))).not.toThrow();
  });

  it('accepts a whole pack whose duty is not met and leaves the verdict to arithmetic', () => {
    const { items, anchor, head } = issued();
    const met = claimFor(items, anchor, head, { required: 1 });
    const short = claimFor(items, anchor, head, { required: 3_600 });
    // One second of held evidence against a period of an hour: the reader of the container refuses
    // nothing, because the document says what it means and means it consistently, and the answer the
    // reader came for comes out of the comparison `pack.cddl` declines to make for anybody.
    expect(() => readSpan(items, met)).not.toThrow();
    expect(() => readSpan(items, short)).not.toThrow();
    expect(meetsDuty(met)).toBe(true);
    expect(meetsDuty(short)).toBe(false);
  });
});
