import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import { Tag, encode, defaultEncodeOptions, encodedNumber } from 'cbor2';
import { sortCoreDeterministic } from 'cbor2/sorts';
import { cddlRule, memberDeclarations, required } from './cddl.js';
import { ALG_EDDSA, COSE_HEADER_ALG, COSE_HEADER_CONTENT_TYPE, COSE_HEADER_KID } from '../src/cose.js';
import {
  DECLARED_PACK_PROTECTED_LABELS,
  PACK_CHAIN_MEMBERS,
  PACK_CONTENT_TYPE,
  PACK_DUTY_MEMBERS,
  PACK_ITEM_MEMBERS,
  PACK_MANIFEST_MEMBERS,
  PACK_SPAN_MEMBERS,
  decodePack,
  packRecordDigest,
  packSigStructure,
  verifyPack,
  type PackVerifyOptions,
} from '../src/pack.js';
import { EXPORT_CONTENT_TYPE } from '../src/export.js';
import { sealDeploymentManifest } from '../src/manifest-seal.js';
import { ReceiptError } from '../src/errors.js';
import {
  decodeCanonical,
  encodeCanonical,
  fromBase64Url,
  issueReceipt,
  signingKeyFromSeed,
  toHex,
  type PackItem,
  type PackManifest,
  type ReceiptPayload,
  type ReceiptPayloadV1,
  type SigningKey,
} from '../src/index.js';

/**
 * The pack container, read.
 *
 * `pack.cddl` is the normative statement of the layout and this file holds it against the reader in
 * `src/pack.ts`, in both directions. Which members each closed map declares, which positions the format types
 * as integers, which widths it writes beside a value and which ceiling it gives an id are read out of the CDDL
 * rather than restated here, because a roster typed out in this file would keep passing the day the format
 * gained a position and the reader did not notice. The format's own twin and the specification's prose are held
 * by their suites; what belongs here is the enforcement.
 *
 * Every refusal is reached by editing one position of an honest document and re-sealing it, so the fault a case
 * reports can only be the edit. An unsigned mutant would answer `INVALID_SIGNATURE` for every position in the
 * file and the suite would be measuring the signature instead of the layout. The floating-point sweep is the
 * one case that cannot use the package's canonical writer at all, because that writer has an integer spelling
 * for every whole number and always takes it, so those bytes are produced by the plain one, which keeps the
 * major type a value was given.
 *
 * There is no writer to call. Nothing in this repository assembles a pack, so the bytes every case runs on are
 * built here, one Map per declared map, and signed over the framing `pack.ts` publishes. The chain is rebuilt
 * from section 5.2 of `docs/receipt-spec.md`, which this file spells out on its own and then holds against
 * `packRecordDigest` and against the record images in `packages/fixtures/data/chain-v1.json`, so that a digest
 * the reader reproduces is tied to two other statements of the framing rather than to itself.
 */
const packCddlPath = fileURLToPath(new URL('../pack.cddl', import.meta.url));
const vectorsPath = fileURLToPath(new URL('../../fixtures/data/chain-v1.json', import.meta.url));
const specPath = fileURLToPath(new URL('../../../docs/receipt-spec.md', import.meta.url));
const readerSourcePath = fileURLToPath(new URL('../src/pack.ts', import.meta.url));
const CDDL = readFileSync(packCddlPath, 'utf8');

/** The rule one map of this format is, and the roster `pack.ts` claims for it. */
const CLOSED_MAPS: Array<{ rule: string; members: readonly string[]; name: string }> = [
  { rule: 'Ashaveri-Pack-Manifest', members: PACK_MANIFEST_MEMBERS, name: 'PACK_MANIFEST_MEMBERS' },
  { rule: 'PackSpan', members: PACK_SPAN_MEMBERS, name: 'PACK_SPAN_MEMBERS' },
  { rule: 'PackChain', members: PACK_CHAIN_MEMBERS, name: 'PACK_CHAIN_MEMBERS' },
  { rule: 'PackDuty', members: PACK_DUTY_MEMBERS, name: 'PACK_DUTY_MEMBERS' },
  { rule: 'PackItem', members: PACK_ITEM_MEMBERS, name: 'PACK_ITEM_MEMBERS' },
];

/** The text of one map block of `pack.cddl`, with this file named when the rule is not there. */
function packRule(rule: string): string {
  if (!CDDL.includes(`${rule} = {`)) throw new Error(`${rule} is not declared in ${packCddlPath}`);
  return cddlRule(CDDL, rule);
}

/** The members one block declares, and the run stops on a block that names none. */
function packMembers(rule: string): string[] {
  const members = memberDeclarations(packRule(rule)).map((member) => member.name);
  if (members.length === 0) throw new Error(`the ${rule} block declares no members`);
  return members;
}

/** Every rule the file opens as a map, read off the text so a map added later is swept the day it lands. */
function packMapRuleNames(): string[] {
  const names: string[] = [];
  for (const line of CDDL.split('\n')) {
    const found = /^([A-Za-z][A-Za-z0-9_-]*) = \{/u.exec(line);
    if (found) names.push(found[1]!);
  }
  if (names.length === 0) throw new Error(`no map rule is declared in ${packCddlPath}`);
  return names;
}

/** The type expression one member of one rule carries. */
function memberType(rule: string, member: string): string {
  const found = memberDeclarations(packRule(rule)).find((one) => one.name === member);
  return required(found, `${rule}.${member} is declared in no block this reader can find`).type;
}

/** The manifest's members that open another map of the file, and whether as an array of them. */
function nestedRules(): Array<{ member: string; rule: string }> {
  const nested: Array<{ member: string; rule: string }> = [];
  for (const member of memberDeclarations(packRule('Ashaveri-Pack-Manifest'))) {
    const one = /^([A-Z][A-Za-z0-9_-]*)$/u.exec(member.type);
    if (one) {
      nested.push({ member: member.name, rule: one[1]! });
      continue;
    }
    const many = /^\[\+\s+([A-Z][A-Za-z0-9_-]*)\]$/u.exec(member.type);
    if (many) {
      nested.push({ member: member.name, rule: many[1]! });
      continue;
    }
    if (/^(?:int|tstr|bstr\b|-?\d+)/u.test(member.type)) continue;
    throw new Error(`${member.name} is declared as "${member.type}", which this reader does not read as one rule`);
  }
  if (nested.length === 0) throw new Error(`the manifest of ${packCddlPath} opens no map`);
  return nested;
}

const INTEGER_TYPE = /^(?:int|-?\d+)$/u;

/**
 * Every position the format types as an integer, with the dotted name a reader of a document uses. Derived from
 * the blocks, so a position arriving in the CDDL reaches the sweep below with no edit here, and the roster is
 * pinned separately as a fact about the file.
 */
function integerPositions(): string[] {
  const byMember = new Map(nestedRules().map((one) => [one.member, one.rule]));
  const positions: string[] = [];
  for (const member of memberDeclarations(packRule('Ashaveri-Pack-Manifest'))) {
    if (INTEGER_TYPE.test(member.type)) {
      positions.push(member.name);
      continue;
    }
    const rule = byMember.get(member.name);
    if (rule === undefined) continue;
    for (const inner of memberDeclarations(packRule(rule))) {
      if (INTEGER_TYPE.test(inner.type)) positions.push(`${member.name}.${inner.name}`);
    }
  }
  if (positions.length === 0) throw new Error(`no position of ${packCddlPath} is typed as an integer`);
  return positions;
}

/** The integer labels one block declares its members by, sign included. */
function integerLabels(block: string): number[] {
  const labels: number[] = [];
  for (const line of block.split('\n').slice(1)) {
    const declaration = line.split(';')[0]!;
    if (declaration.trim() === '') continue;
    const found = /^\s*(-?\d+)\s*:\s*[^,\s][^,]*,?\s*$/u.exec(declaration);
    if (!found) throw new Error(`this reader takes one member per line, labelled by an integer, and cannot read "${declaration.trim()}"`);
    labels.push(Number(found[1]));
  }
  if (labels.length === 0) throw new Error('the block declares no member by integer label');
  return labels;
}

/** The quoted value one integer label carries, which is how a content type is read out of a header. */
function labeledLiteral(block: string, label: number): string {
  const found = new RegExp(`^\\s*${label}\\s*:\\s*"([^"]*)"`, 'mu').exec(block);
  if (!found) throw new Error(`the block carries no quoted value at label ${label}`);
  return found[1]!;
}

/** The width one member's type expression states, or the throw naming what it stated instead. */
function declaredWidth(rule: string, member: string): number {
  const type = memberType(rule, member);
  const found = /^bstr \.size (\d+)$/u.exec(type);
  if (!found) throw new Error(`${rule}.${member} is typed "${type}", which states no fixed width`);
  return Number(found[1]);
}

/** The CDDL's full-line comments as prose, which is what a stranger reading the format actually reads. */
function cddlProse(): string {
  return CDDL.split('\n')
    .filter((line) => line.startsWith(';'))
    .map((line) => line.slice(1))
    .join('\n')
    .replace(/\s+/gu, ' ')
    .trim();
}

const INTEGER_POSITIONS = integerPositions();
const HEADER_BLOCK = packRule('Ashaveri-Pack-Protected-Header');
const ID_RANGE = (() => {
  const type = memberType('PackItem', 'id');
  const found = /^tstr \.size \((\d+)\.\.(\d+)\)$/u.exec(type);
  if (!found) throw new Error(`PackItem.id is typed "${type}", which states no byte range`);
  return { min: Number(found[1]), max: Number(found[2]) };
})();
const DIGEST_BYTES = declaredWidth('PackItem', 'prev');
const KID_BYTES = Number(required(/4:\s*bstr \.size (\d+)/u.exec(HEADER_BLOCK)?.[1], 'the signed header declares no kid width'));
const SIGNATURE_BYTES = Number(required(/signature: bstr \.size (\d+)/u.exec(CDDL)?.[1], 'the pack states no signature width'));

/** The positions the manifest fixes at a width, at every level a reader closes. */
const WIDTH_POSITIONS: string[] = [];
for (const rule of packMapRuleNames()) {
  for (const member of memberDeclarations(packRule(rule))) {
    if (!/^bstr \.size \d+$/u.test(member.type)) continue;
    WIDTH_POSITIONS.push(rule === 'PackItem' ? `items.${member.name}` : member.name);
  }
}

/* -------------------------------------------------------------------------- */
/* The documents every case edits by one position.                              */
/* -------------------------------------------------------------------------- */

const KEY = signingKeyFromSeed(new Uint8Array(32).fill(11));
const OTHER = signingKeyFromSeed(new Uint8Array(32).fill(12));
const BASE = 1_772_000_000;
const SPAN_FROM = BASE - 60;
const SPAN_TO = BASE + 3;

/** The three stamps every case below starts from, one second apart as the store chains them. */
const ENTRIES = [
  { id: 'receipt-0', iat: BASE, nonce: 1 },
  { id: 'receipt-1', iat: BASE + 1, nonce: 2 },
  { id: 'receipt-2', iat: BASE + 2, nonce: 3 },
];

function bytesOf(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** The receipt payload attested by one item, with only the stamp and a nonce moving per case. */
function receiptPayload(iat: number, nonce: number): ReceiptPayloadV1 {
  const digest = sha256(new Uint8Array([nonce]));
  return {
    v: 1,
    iss: 'ashaveri-pack-reader',
    ins: 'cvm-pack-1',
    iat,
    nce: new Uint8Array(16).fill(nonce),
    req: digest,
    res: digest,
    mdl: 'mock-model-1',
    wts: digest,
    meas: { tee: 'software', m: digest },
    att: { d: digest, ts: iat - 60, url: 'https://inference.ashaveri.example/v1/attestation' },
    epk: 0,
    tok: { p: 1, c: 1 },
  };
}

/**
 * The framing of section 5.2, spelled out here independently of `pack.ts`: kind byte, predecessor, the stamp as
 * eight big-endian bytes, the byte length of the id as two big-endian bytes, the id, the receipt bytes. The
 * reader's own digest function is compared against this one and against the published record images below,
 * which is what keeps a chain that closes from being a tautology.
 */
type FrameInput = Pick<PackItem, 'id' | 'iat' | 'prev' | 'receipt'>;

function framingInput(item: FrameInput): Uint8Array {
  const id = bytesOf(item.id);
  const out = new Uint8Array(1 + DIGEST_BYTES + 8 + 2 + id.length + item.receipt.length);
  const view = new DataView(out.buffer, out.byteOffset);
  out[0] = 0;
  out.set(item.prev, 1);
  view.setBigUint64(1 + DIGEST_BYTES, BigInt(item.iat));
  view.setUint16(1 + DIGEST_BYTES + 8, id.length);
  out.set(id, 1 + DIGEST_BYTES + 8 + 2);
  out.set(item.receipt, 1 + DIGEST_BYTES + 8 + 2 + id.length);
  return out;
}

function framedDigest(item: FrameInput): Uint8Array {
  return sha256(framingInput(item));
}

/**
 * Receipts from the package's own writer, chained in the order given from `anchor`. `attest` is the payload
 * each record carries, so a case can chain marked receipts, which changes their bytes and so every digest
 * after them. An entry may name the key that signed it, which is how a chain crosses a rotation: the records
 * of the retired epoch and those of the key that replaced it sit in one run, and each is signed by the key its
 * own header ends up naming.
 */
function chained(
  entries: Iterable<{ id: string; iat: number; nonce: number; key?: SigningKey }>,
  anchor = new Uint8Array(DIGEST_BYTES),
  key: SigningKey = KEY,
  attest: (iat: number, nonce: number) => ReceiptPayload = receiptPayload,
): { items: PackItem[]; anchor: Uint8Array; head: Uint8Array } {
  const items: PackItem[] = [];
  let prev: Uint8Array = anchor;
  for (const entry of entries) {
    const item: PackItem = {
      id: entry.id,
      iat: entry.iat,
      prev,
      receipt: issueReceipt(attest(entry.iat, entry.nonce), entry.key ?? key),
    };
    items.push(item);
    prev = framedDigest(item);
  }
  return { items, anchor, head: prev };
}

/** The manifest as the shape the reader returns, honest in every relation the format states. */
function manifestValue(over: Partial<PackManifest> = {}): PackManifest {
  const run = chained(ENTRIES);
  return {
    v: 1,
    at: SPAN_TO,
    span: { from: SPAN_FROM, to: SPAN_TO },
    chain: { anchor: run.anchor, head: run.head },
    duty: { art: '19(1)', rev: SPAN_TO - 30, required: 3_600, held: SPAN_TO - BASE },
    items: run.items,
    ...over,
  };
}

/** The manifest as the CBOR maps the format declares, one Map per map so key order is bytewise. */
function manifestMap(manifest: PackManifest): Map<string, unknown> {
  const item = (one: PackItem): Map<string, unknown> =>
    new Map<string, unknown>([
      ['id', one.id],
      ['iat', one.iat],
      ['prev', one.prev],
      ['receipt', one.receipt],
    ]);
  return new Map<string, unknown>([
    ['v', manifest.v],
    ['at', manifest.at],
    ['span', new Map<string, unknown>([['from', manifest.span.from], ['to', manifest.span.to]])],
    ['chain', new Map<string, unknown>([['anchor', manifest.chain.anchor], ['head', manifest.chain.head]])],
    [
      'duty',
      new Map<string, unknown>([
        ['art', manifest.duty.art],
        ['rev', manifest.duty.rev],
        ['required', manifest.duty.required],
        ['held', manifest.duty.held],
      ]),
    ],
    ['items', manifest.items.map(item)],
  ]);
}

function packHeader(kid: Uint8Array, contentType: string = PACK_CONTENT_TYPE): Map<number, unknown> {
  return new Map<number, unknown>([
    [COSE_HEADER_ALG, ALG_EDDSA],
    [COSE_HEADER_CONTENT_TYPE, contentType],
    [COSE_HEADER_KID, kid],
  ]);
}

/**
 * A `COSE_Sign1-Pack-COSE`, tagged, signed by `key` over the framing this format publishes. `write` is the
 * encoder, and a case that needs a number to keep the major type it was given passes the plain one.
 */
function seal(
  payloadBytes: Uint8Array,
  key: SigningKey,
  header: Map<unknown, unknown> = packHeader(key.kid),
  unprotected = new Map<unknown, unknown>(),
  write: (value: unknown) => Uint8Array = encodeCanonical,
): Uint8Array {
  const protectedBytes = write(header);
  const signature = ed25519.sign(packSigStructure(protectedBytes, payloadBytes), key.privateKey);
  return write(new Tag(18, [protectedBytes, unprotected, payloadBytes, signature]));
}

/** A pack the issuer signed, from the manifest shape this file builds. */
function signPack(manifest: PackManifest, key: SigningKey = KEY): Uint8Array {
  return seal(encodeCanonical(manifestMap(manifest)), key);
}

/**
 * A span that crosses a key rotation, assembled rather than described: the first `older` receipts are signed by
 * the key a deployment retired inside the window and the rest by the key that replaced it, and the chain is
 * rebuilt over both, so each item's header ends up naming the key that signed it. The envelope is signed by the
 * current key, which is the shape of the honest pack the reader takes one key could not verify.
 */
function rotatedManifest(older: number): PackManifest {
  const run = chained(ENTRIES.map((one, index) => ({ ...one, key: index < older ? OTHER : KEY })));
  return manifestValue({ chain: { anchor: run.anchor, head: run.head }, items: run.items });
}

/**
 * A caller's retained key set, answered by the kid a header names, recording every kid it was asked for so a
 * case can see which side of the container reached it and in what order.
 */
function keySet(keys: readonly SigningKey[]): { resolveKey: (kid: Uint8Array) => Uint8Array | undefined; asked: string[] } {
  const byKid = new Map(keys.map((one) => [toHex(one.kid), one.publicKey]));
  const asked: string[] = [];
  return {
    asked,
    resolveKey: (kid) => {
      const name = toHex(kid);
      asked.push(name);
      return byKid.get(name);
    },
  };
}

/** A resolver that reports its own consultation, which is how an ordering is proved rather than asserted. */
function neverAsked(): (kid: Uint8Array) => Uint8Array | undefined {
  return () => {
    throw new Error('a resolver was consulted for a document this reader should never have opened');
  };
}

/**
 * One fault, which is the edit, with nothing else moved and the signature still good: the payload is decoded
 * back into maps, edited, re-encoded and re-signed, so a case below can only be answered by the rule it broke.
 */
function reSealed(bytes: Uint8Array, mutate: (root: Map<unknown, unknown>) => void, write = encodeCanonical, key: SigningKey = KEY): Uint8Array {
  const root = rootOf(bytes);
  mutate(root);
  return seal(write(root), key, packHeader(key.kid), new Map(), write);
}

/** Bytes with every number written as the major type it was given, which the canonical writer refuses to do. */
function encodeKeepingTypes(value: unknown): Uint8Array {
  return new Uint8Array(encode(value, { ...defaultEncodeOptions, sortKeys: sortCoreDeterministic }));
}

function rootOf(bytes: Uint8Array): Map<unknown, unknown> {
  const root = decodeCanonical(payloadOf(bytes));
  if (!(root instanceof Map)) throw new Error('the document this file builds has no manifest map to edit');
  return root;
}

function elementsOf(bytes: Uint8Array): unknown[] {
  const top = decodeCanonical(bytes);
  const contents = (top as { contents?: unknown }).contents;
  if (!Array.isArray(contents)) throw new Error('the document this file builds is not a four-element envelope');
  return contents;
}

function payloadOf(bytes: Uint8Array): Uint8Array {
  return elementsOf(bytes)[2] as Uint8Array;
}

function child(value: unknown, key: string | number): unknown {
  if (value instanceof Map) return value.get(key);
  if (Array.isArray(value)) return value[Number(key)];
  throw new Error(`${String(key)} is not a member of anything this case edits`);
}

function mapOf(value: unknown, position: string): Map<unknown, unknown> {
  if (!(value instanceof Map)) throw new Error(`${position} is not a map in the document this case builds`);
  return value;
}

function itemOf(root: Map<unknown, unknown>, index: number): Map<unknown, unknown> {
  const items = child(root, 'items');
  const one = Array.isArray(items) ? items[index] : undefined;
  if (!(one instanceof Map)) throw new Error(`the built document carries no item at ${String(index)}`);
  return one;
}

function spanOf(root: Map<unknown, unknown>): Map<unknown, unknown> {
  return mapOf(child(root, 'span'), 'span');
}

function dutyOf(root: Map<unknown, unknown>): Map<unknown, unknown> {
  return mapOf(child(root, 'duty'), 'duty');
}

function chainOf(root: Map<unknown, unknown>): Map<unknown, unknown> {
  return mapOf(child(root, 'chain'), 'chain');
}

/** The map one dotted position of the format lives in, so a sweep can reach a position at any depth. */
function holderOf(root: Map<unknown, unknown>, position: string): { map: Map<unknown, unknown>; member: string } {
  const parts = position.split('.');
  if (parts[0] === 'items') {
    return { map: itemOf(root, 0), member: required(parts[1], `the position ${position} names no member of an item`) };
  }
  if (parts.length === 1) return { map: root, member: parts[0]! };
  return { map: mapOf(child(root, parts[0]!), parts[0]!), member: required(parts[1], `the position ${position} names no member`) };
}

function thrownBy(fn: () => unknown): unknown {
  try {
    fn();
    return null;
  } catch (err) {
    return err;
  }
}

function codeOf(fn: () => unknown): string {
  const thrown = thrownBy(fn);
  if (thrown instanceof ReceiptError) return thrown.code;
  return thrown instanceof Error ? `UNCODED:${thrown.message}` : `THREW:${String(thrown)}`;
}

/** The code a refusal carries, or the word this file uses when the reader answered nothing. */
function answered(fn: () => unknown): string {
  const thrown = thrownBy(fn);
  return thrown === null ? 'accepted' : thrown instanceof ReceiptError ? thrown.code : `UNCODED:${String(thrown)}`;
}

function fromHex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

describe('the pack reader and the format it reads', () => {
  it('closes the maps the CDDL closes, at the widths and the ceiling it writes', () => {
    for (const binding of CLOSED_MAPS) {
      expect([...binding.members], `pack.ts's ${binding.name} is not the ${binding.rule} roster`).toEqual(packMembers(binding.rule));
    }
    // Every map of the format, so a map added later cannot arrive unclosed by this reader and unasked of here.
    expect(packMapRuleNames().sort(), 'the maps this reader holds are not every map the format declares').toEqual(
      [...CLOSED_MAPS.map((one) => one.rule), 'Ashaveri-Pack-Protected-Header'].sort(),
    );
    for (const rule of packMapRuleNames()) {
      expect(packRule(rule).includes('...'), `${rule} carries an open member this reader would have to forget`).toBe(false);
    }
    expect(
      [...DECLARED_PACK_PROTECTED_LABELS].sort((a, b) => a - b),
      'the labels the reader closes against are not the header labels the format declares',
    ).toEqual(integerLabels(HEADER_BLOCK).slice().sort((a, b) => a - b));
    expect(labeledLiteral(HEADER_BLOCK, COSE_HEADER_CONTENT_TYPE), 'the content type the reader names is not the one the format declares').toBe(PACK_CONTENT_TYPE);
    expect(PACK_CONTENT_TYPE).toBe('ashaveri/pack');
    expect(DIGEST_BYTES).toBe(32);
    expect(SIGNATURE_BYTES).toBe(64);
    expect(KID_BYTES).toBe(32);
    expect(ID_RANGE).toEqual({ min: 1, max: 65_535 });
    expect(WIDTH_POSITIONS.sort()).toEqual(['anchor', 'head', 'items.prev']);
    // What the format leaves unclosed, in its own words: the one map a signer fills at will.
    expect(CDDL).toContain('unprotected: { * any => any }');
    expect(cddlProse()).toContain('they are the authority and this file is wrong');
  });

  it('refuses a float at every position the format types as an integer, in a value and in a key alike', () => {
    expect(INTEGER_POSITIONS).toEqual(['v', 'at', 'span.from', 'span.to', 'duty.rev', 'duty.required', 'duty.held', 'items.iat']);
    const good = signPack(manifestValue());
    for (const position of INTEGER_POSITIONS) {
      for (const [width, floated] of [
        ['half-precision', encodedNumber(2, 'f16')],
        ['single-precision', encodedNumber(2, 'f32')],
        ['double-precision', encodedNumber(2, 'f64')],
        ['negative zero', encodedNumber(-0, 'f16')],
      ] as Array<[string, unknown]>) {
        const bytes = reSealed(good, (root) => {
          const holder = holderOf(root, position);
          holder.map.set(holder.member, floated);
        }, encodeKeepingTypes);
        expect(answered(() => decodePack(bytes)), `${position} written as a ${width} float was accepted`).toBe('PACK_BAD_MANIFEST');
        expect(answered(() => verifyPack(bytes, { publicKey: KEY.publicKey })), `${position} as a ${width} float answered differently once verified`).toBe('PACK_BAD_MANIFEST');
      }
      // The same rule on the path this package's own writer takes, which is the one a value no integer spells
      // uses: a half of the class the canonical encoder can produce, and refused by the same decode.
      expect(
        answered(() => decodePack(reSealed(good, (root) => {
          const holder = holderOf(root, position);
          holder.map.set(holder.member, 1.5);
        }))),
        `${position} of 1.5 was accepted`,
      ).toBe('PACK_BAD_MANIFEST');
      // A key is where the distinction disappears by the time anything could ask which bytes wrote it, so the
      // decode is the last point at which the rule can be enforced at all.
      expect(
        answered(() => decodePack(reSealed(good, (root) => {
          const holder = holderOf(root, position);
          holder.map.set(encodedNumber(7, 'f64'), holder.member);
        }, encodeKeepingTypes))),
        'a float as a map key was accepted',
      ).toBe('PACK_BAD_MANIFEST');
    }
    // A header label written as a float is the same fault at the position the signature hashes, and the shape
    // that reads as a well-formed header to anything looking at the map afterwards: the float `1.0` and the
    // integer `1` are one `Map` slot, so the refusal has to come from the bytes.
    const floatedLabel = new Map<unknown, unknown>([
      [encodedNumber(COSE_HEADER_ALG, 'f16'), ALG_EDDSA],
      [COSE_HEADER_CONTENT_TYPE, PACK_CONTENT_TYPE],
      [COSE_HEADER_KID, KEY.kid],
    ]);
    const floatedHeader = seal(encodeCanonical(manifestMap(manifestValue())), KEY, floatedLabel, new Map(), encodeKeepingTypes);
    const headerThrown = thrownBy(() => decodePack(floatedHeader)) as ReceiptError;
    expect(headerThrown.code).toBe('PACK_BAD_HEADER');
    expect(headerThrown.message).toContain('floating point');
    // The control: the same values as integers, in the same positions, which is what a real pack carries.
    expect(() => decodePack(good)).not.toThrow();
    expect(() => verifyPack(good, { publicKey: KEY.publicKey })).not.toThrow();
  });

  it('refuses a member no map of this version defines, at every level including the signed header', () => {
    const good = signPack(manifestValue());
    const levels: Array<[string, (root: Map<unknown, unknown>) => void, string]> = [
      ['the manifest', (root) => root.set('surprise', 'x'), "manifest carries a member this version does not define: 'surprise'"],
      ['the span', (root) => spanOf(root).set('surprise', 'x'), "span carries a member this version does not define: 'surprise'"],
      ['the chain', (root) => chainOf(root).set('surprise', 'x'), "chain carries a member this version does not define: 'surprise'"],
      ['the duty', (root) => dutyOf(root).set('met', true), "duty carries a member this version does not define: 'met'"],
      ['an item', (root) => itemOf(root, 0).set('surprise', 'x'), "items\\[0\\] carries a member this version does not define: 'surprise'"],
    ];
    for (const [name, mutate, phrase] of levels) {
      const bytes = reSealed(good, mutate);
      const thrown = thrownBy(() => decodePack(bytes)) as ReceiptError;
      expect(thrown, `an undefined member of ${name} was accepted`).toBeInstanceOf(ReceiptError);
      expect(thrown.message, name).toContain(phrase.replace(/\\\[/gu, '[').replace(/\\\]/gu, ']'));
      expect(thrown.code, `${name} answered another code`).toBe('PACK_BAD_MANIFEST');
      expect(answered(() => verifyPack(bytes, { publicKey: KEY.publicKey })), `${name} answered differently once verified`).toBe('PACK_BAD_MANIFEST');
    }
    // The header closes under the stronger of the two reasons: its bytes are hashed into the `Sig_structure`,
    // so a fourth label is an authenticated parameter and a reader that took the three it knows would hand on
    // a document other than the one the issuer signed.
    const fourthLabel = seal(encodeCanonical(manifestMap(manifestValue())), KEY, packHeader(KEY.kid).set(5, 'what'));
    const thrown = thrownBy(() => verifyPack(fourthLabel, { publicKey: KEY.publicKey })) as ReceiptError;
    expect(thrown.code).toBe('PACK_BAD_HEADER');
    expect(thrown.message).toMatch(/does not define: the numeric key 5/u);
  });

  it('names a pack by its content type before it consults a key', () => {
    const payload = encodeCanonical(manifestMap(manifestValue()));
    // The same key signs all four containers, so the `typ` is the only thing that keeps a reader from reporting
    // a pack as an attestation about one response, or a handover as a span, and both documents pass.
    for (const [name, contentType] of [
      ['a receipt', 'ashaveri/receipt'],
      ['an export', EXPORT_CONTENT_TYPE],
      ['a deployment manifest', 'ashaveri/deployment-manifest'],
    ] as const) {
      const bytes = seal(payload, KEY, packHeader(KEY.kid, contentType));
      const thrown = thrownBy(() => verifyPack(bytes, { publicKey: OTHER.publicKey })) as ReceiptError;
      expect(thrown, `${name} was read as a pack`).toBeInstanceOf(ReceiptError);
      expect(thrown.code, `${name} answered another code`).toBe('PACK_BAD_HEADER');
      expect(thrown.message, `${name} did not name its content type`).toContain(`typ=${contentType}`);
    }
    // Before any member of the manifest is read, whatever else the document holds: a payload that is not a
    // manifest at all, under another container's type, is answered as the container it is not.
    expect(codeOf(() => decodePack(seal(encodeCanonical('a receipt payload'), KEY, packHeader(KEY.kid, 'ashaveri/receipt'))))).toBe('PACK_BAD_HEADER');
    // A sealed deployment manifest is the fourth container, reached through its own writer rather than
    // hand-built here, so the sentence about it is about the bytes a reader would actually meet.
    expect((thrownBy(() => verifyPack(sealDeploymentManifest(bytesOf('{"v":1}'), KEY), { publicKey: KEY.publicKey })) as ReceiptError).message).toMatch(/typ=ashaveri\/deployment-manifest/u);
    // The key designation is answered after the type, and the two are different findings: this document is a
    // pack, and the key in the reader's hand is not the one it names.
    expect(codeOf(() => verifyPack(signPack(manifestValue()), { publicKey: OTHER.publicKey }))).toBe('PACK_KID_MISMATCH');
  });

  it('refuses an envelope that is not one, whatever it holds', () => {
    expect(codeOf(() => decodePack(new Uint8Array([0xff])))).toBe('PACK_MALFORMED_CBOR');
    expect((thrownBy(() => decodePack(encodeCanonical([1, 2, 3]))) as ReceiptError).message).toMatch(/tag 18/u);
    const [prot, , payload, signature] = elementsOf(signPack(manifestValue()));
    expect(codeOf(() => decodePack(encodeCanonical(new Tag(18, [prot, new Map(), payload]))))).toBe('NOT_COSE_SIGN1');
    expect(codeOf(() => decodePack(encodeCanonical(new Tag(18, [prot, new Map(), payload, new Uint8Array(SIGNATURE_BYTES - 1)]))))).toBe('NOT_COSE_SIGN1');
    // A four-element envelope whose protected bytes hold no map is answered as a header, not as an envelope:
    // the array and its widths are right, and what fails is the signed header the format declares.
    expect(codeOf(() => decodePack(encodeCanonical(new Tag(18, [new Uint8Array(4), new Map(), payload, signature]))))).toBe('PACK_BAD_HEADER');
    expect(codeOf(() => decodePack(payload as Uint8Array))).toBe('NOT_COSE_SIGN1');
    const algSwapped = packHeader(KEY.kid, PACK_CONTENT_TYPE).set(COSE_HEADER_ALG, -7);
    expect((thrownBy(() => verifyPack(seal(payload as Uint8Array, KEY, algSwapped), { publicKey: KEY.publicKey })) as ReceiptError).message).toMatch(/alg=-7/u);
    // The control, which is the same payload under a header this reader accepts.
    expect(() => verifyPack(seal(payload as Uint8Array, KEY), { publicKey: KEY.publicKey })).not.toThrow();
  });

  it('reads a whole pack and hands back the run and the window as two findings', () => {
    const verifiedPack = verifyPack(signPack(manifestValue()), { publicKey: KEY.publicKey });
    expect(verifiedPack.header.contentType).toBe(PACK_CONTENT_TYPE);
    expect(verifiedPack.manifest.at).toBe(SPAN_TO);
    expect(verifiedPack.manifest.items.map((one) => one.id)).toEqual(['receipt-0', 'receipt-1', 'receipt-2']);
    // The two fields, and the reason they are two: one is established by the walk, the other is the
    // manifest's own claim about the period, and a caller that printed either alone would be saying more than
    // the bytes it holds can carry.
    expect(Object.keys(verifiedPack).sort()).toEqual(['envelope', 'header', 'manifest', 'outcome']);
    expect(Object.keys(verifiedPack.outcome).sort()).toEqual(['span', 'walked']);
    expect(verifiedPack.outcome.span).toBe(verifiedPack.manifest.span);
    expect(verifiedPack.outcome.walked.map((one) => one.item.id)).toEqual(['receipt-0', 'receipt-1', 'receipt-2']);
    for (const one of verifiedPack.outcome.walked) {
      expect(one.receipt.payload.iat).toBe(one.item.iat);
      expect(one.receipt.header.kid).toEqual(verifiedPack.header.kid);
    }
    // Nothing in the report is a conclusion the reader drew: no verdict on the duty, on completeness at the
    // source, or on freshness, and the integers behind those questions come back as they were signed.
    expect(verifiedPack.manifest.duty).toEqual({ art: '19(1)', rev: SPAN_TO - 30, required: 3_600, held: SPAN_TO - BASE });
    const printed = JSON.stringify(verifiedPack, (_key, value: unknown) => (value instanceof Uint8Array ? 'bytes' : value)).toLowerCase();
    for (const word of ['"met"', 'requiredseconds', 'heldseconds', 'qualified', 'complete', 'fresh', 'verdict', '"passed"', '"satisfied"']) {
      expect(printed, `the reader's own report carries ${word}`).not.toContain(word);
    }
  });

  it('walks the links and not the array, from either shape of anchor', () => {
    const run = chained(ENTRIES);
    const shuffled = manifestValue({ items: [run.items[2]!, run.items[0]!, run.items[1]!] });
    expect(verifyPack(signPack(shuffled), { publicKey: KEY.publicKey }).outcome.walked.map((one) => one.item.id)).toEqual(['receipt-0', 'receipt-1', 'receipt-2']);
    // A retirement put a seam in front of the run instead of thirty-two zero bytes: the reader starts where the
    // manifest says to and does not have to know which of the two happened.
    const seam = sha256(bytesOf('the seam a trim record carried'));
    const afterRetirement = chained(ENTRIES, seam);
    const retired = manifestValue({ chain: { anchor: afterRetirement.anchor, head: afterRetirement.head }, items: afterRetirement.items });
    expect(() => verifyPack(signPack(retired), { publicKey: KEY.publicKey })).not.toThrow();
    // A run of one item is a whole walk: the item whose `prev` is the anchor is first and the item whose own
    // digest is the head is last, and here they are the same item.
    const single = chained([ENTRIES[0]!]);
    const oneItem = manifestValue({ chain: { anchor: single.anchor, head: single.head }, items: single.items });
    expect(verifyPack(signPack(oneItem), { publicKey: KEY.publicKey }).outcome.walked.map((one) => one.item.id)).toEqual(['receipt-0']);
  });

  it('refuses a gap, a forged close, a fork and an item the walk never reaches', () => {
    const run = chained(ENTRIES);
    const honest = manifestValue();
    // A record lifted out of the middle: what remains is whole by its own digest, and the walk stops short.
    const gap = manifestValue({ items: [run.items[0]!, run.items[2]!] });
    const broken = thrownBy(() => verifyPack(signPack(gap), { publicKey: KEY.publicKey })) as ReceiptError;
    expect(broken.code).toBe('PACK_CHAIN_BROKEN');
    expect(broken.message).toMatch(/stopped at a digest that is not the head/u);
    // The same omission with the hole closed by re-chaining, which is the forgery the signed head exists to
    // defeat: the links are perfect and the run is still short of the endpoint the writer signed.
    const rechained = chained([ENTRIES[0]!, ENTRIES[2]!]);
    expect(codeOf(() => verifyPack(signPack(manifestValue({ items: rechained.items })), { publicKey: KEY.publicKey }))).toBe('PACK_CHAIN_BROKEN');
    // What the signed endpoints cannot reach is the same omission with the head moved to match it, because the
    // reader is not handed a copy of an earlier head to compare against. The run then walks clean, and the
    // report says exactly what it can: a chain that closed, over the window the manifest names.
    const rewritten = manifestValue({ chain: { anchor: rechained.anchor, head: rechained.head }, items: rechained.items });
    const shortened = verifyPack(signPack(rewritten), { publicKey: KEY.publicKey });
    expect(shortened.outcome.walked.map((one) => one.item.id)).toEqual(['receipt-0', 'receipt-2']);
    expect(shortened.outcome.span).toEqual({ from: SPAN_FROM, to: SPAN_TO });
    // Two items claiming one predecessor: the walk would take whichever it met first, so a fork is refused
    // rather than resolved by arrival order.
    const rival: PackItem = { id: 'rival', iat: BASE + 1, prev: run.anchor, receipt: issueReceipt(receiptPayload(BASE + 1, 7), KEY) };
    expect(codeOf(() => verifyPack(signPack(manifestValue({ items: [rival, ...run.items] })), { publicKey: KEY.publicKey }))).toBe('PACK_CHAIN_BROKEN');
    // A receipt parked beside a span it is not part of reaches the head exactly as the honest ones do, because
    // the walk stops where the head is: the count of what it reached is the half with eyes for it.
    const parked: PackItem = { id: 'parked', iat: BASE + 1, prev: sha256(bytesOf('another chain entirely')), receipt: issueReceipt(receiptPayload(BASE + 1, 8), KEY) };
    const unreached = thrownBy(() => verifyPack(signPack(manifestValue({ items: [...run.items, parked] })), { publicKey: KEY.publicKey })) as ReceiptError;
    expect(unreached.code).toBe('PACK_ITEM_UNREACHED');
    expect(unreached.message).toMatch(/parked/u);
    // The control that says those four cases were the edits and nothing else.
    expect(() => verifyPack(signPack(honest), { publicKey: KEY.publicKey })).not.toThrow();
  });

  it('refuses a quantity the format has no kind for, and the contradictions between two signed members', () => {
    const good = signPack(manifestValue());
    const cases: Array<[string, (root: Map<unknown, unknown>) => void, RegExp, string]> = [
      ['a negative assembly stamp', (root) => root.set('at', -1), /no earlier than the epoch/u, 'PACK_BAD_MANIFEST'],
      ['a negative span start', (root) => spanOf(root).set('from', -1), /no earlier than the epoch/u, 'PACK_BAD_MANIFEST'],
      ['a negative span end', (root) => spanOf(root).set('to', -1), /no earlier than the epoch/u, 'PACK_BAD_MANIFEST'],
      ['a negative revision', (root) => dutyOf(root).set('rev', -1), /no earlier than the epoch/u, 'PACK_BAD_MANIFEST'],
      ['a negative period', (root) => dutyOf(root).set('required', -1), /no smaller than zero/u, 'PACK_BAD_MANIFEST'],
      ['a negative figure held', (root) => dutyOf(root).set('held', -1), /no smaller than zero/u, 'PACK_BAD_MANIFEST'],
      ['a negative item stamp', (root) => itemOf(root, 0).set('iat', -1), /no earlier than the epoch/u, 'PACK_BAD_MANIFEST'],
      ['assembly before the span closed', (root) => root.set('at', SPAN_TO - 1), /assembly began at/u, 'PACK_BAD_MANIFEST'],
      ['a revision after the reads', (root) => dutyOf(root).set('rev', SPAN_TO + 1), /postdates the reads/u, 'PACK_BAD_MANIFEST'],
      ['an item at the excluded end of the span', (root) => itemOf(root, 2).set('iat', SPAN_TO), /outside the span/u, 'PACK_BAD_MANIFEST'],
      ['an item before the span', (root) => itemOf(root, 0).set('iat', SPAN_FROM - 1), /outside the span/u, 'PACK_BAD_MANIFEST'],
      ['a held figure younger than the oldest receipt', (root) => dutyOf(root).set('held', SPAN_TO - BASE - 1), /seconds held/u, 'PACK_BAD_MANIFEST'],
      ['no items at all', (root) => root.set('items', []), /non-empty items/u, 'PACK_BAD_MANIFEST'],
      ['items that is not an array', (root) => root.set('items', 'x'), /items must be an array/u, 'PACK_BAD_MANIFEST'],
      ['a missing span', (root) => root.delete('span'), /span must be a map/u, 'PACK_BAD_MANIFEST'],
      ['a missing chain', (root) => root.delete('chain'), /chain must be a map/u, 'PACK_BAD_MANIFEST'],
      ['a missing duty', (root) => root.delete('duty'), /duty must be a map/u, 'PACK_BAD_MANIFEST'],
      ['a digest of another width', (root) => chainOf(root).set('head', new Uint8Array(DIGEST_BYTES - 1)), /head must be a 32-byte bstr/u, 'PACK_BAD_MANIFEST'],
      ['an item predecessor of another width', (root) => itemOf(root, 0).set('prev', new Uint8Array(DIGEST_BYTES + 1)), /prev must be a 32-byte bstr/u, 'PACK_BAD_MANIFEST'],
      ['an empty id', (root) => itemOf(root, 0).set('id', ''), /must be between 1 and 65535 bytes/u, 'PACK_BAD_MANIFEST'],
      ['a receipt that is not bytes', (root) => itemOf(root, 0).set('receipt', 'x'), /receipt must be a bstr/u, 'PACK_BAD_MANIFEST'],
      ['a duty label that is not text', (root) => dutyOf(root).set('art', 19), /duty\.art must be a tstr/u, 'PACK_BAD_MANIFEST'],
      ['a version that is not an integer', (root) => root.set('v', '1'), /v must be an integer pack version/u, 'PACK_BAD_MANIFEST'],
      ['a version this package cannot read', (root) => root.set('v', 2), /version 2 is not a format this package reads/u, 'PACK_UNSUPPORTED_VERSION'],
    ];
    for (const [name, mutate, pattern, code] of cases) {
      const bytes = reSealed(good, mutate);
      const thrown = thrownBy(() => decodePack(bytes)) as ReceiptError;
      expect(thrown, `${name} was accepted`).toBeInstanceOf(ReceiptError);
      expect(thrown.message, name).toMatch(pattern);
      expect(thrown.code, `${name} answered another code`).toBe(code);
      expect(answered(() => verifyPack(bytes, { publicKey: KEY.publicKey })), `${name} answered differently once verified`).toBe(code);
    }
    // Two of these are the answers of the reader with no key in hand, which is the point of the split: a
    // document that contradicts itself does so whoever signed it.
    expect(codeOf(() => decodePack(reSealed(good, (root) => root.set('at', SPAN_TO - 1))))).toBe('PACK_BAD_MANIFEST');
    expect(codeOf(() => decodePack(reSealed(good, (root) => root.set('v', 2))))).toBe('PACK_UNSUPPORTED_VERSION');
  });

  it('keeps the edges the format states rather than tightening them', () => {
    const good = signPack(manifestValue());
    const accepted: Array<[string, (root: Map<unknown, unknown>) => void]> = [
      ['assembly at the instant the span closes', (root) => root.set('at', SPAN_TO)],
      ['a revision at the instant the reads began', (root) => dutyOf(root).set('rev', SPAN_TO)],
      ['a held figure exactly the age of the oldest receipt', (root) => dutyOf(root).set('held', SPAN_TO - BASE)],
      ['an item at the included start of the span, and the held figure that implies', (root) => {
        itemOf(root, 0).set('iat', SPAN_FROM);
        dutyOf(root).set('held', SPAN_TO - SPAN_FROM);
      }],
      ['a period that is nothing', (root) => dutyOf(root).set('required', 0)],
      ['a duty label this estate has never published', (root) => dutyOf(root).set('art', 'an-article-of-some-other-law')],
      ['an id at the ceiling the framing states', (root) => itemOf(root, 0).set('id', 'a'.repeat(ID_RANGE.max))],
    ];
    for (const [name, mutate] of accepted) {
      // The structural edges are answered by the reader with no key, because none of them is a property of a
      // signature. The last two move bytes the chain hashes, so they are asked of `decodePack` alone.
      expect(answered(() => decodePack(reSealed(good, mutate))), `${name} was refused`).toBe('accepted');
    }
  });

  it('keeps the duty readable and never judges it', () => {
    // A period the deployment states and a figure that falls short of it: the document is whole, the arithmetic
    // comes out the way it comes out, and nothing here answers whether the duty was met.
    const short = manifestValue({ duty: { art: '19(1)', rev: SPAN_TO - 30, required: 31_536_000, held: 60 } });
    const met = manifestValue({ duty: { art: '19(1)', rev: SPAN_TO - 30, required: 1, held: SPAN_TO - BASE } });
    const shortRead = verifyPack(signPack(short), { publicKey: KEY.publicKey });
    const metRead = verifyPack(signPack(met), { publicKey: KEY.publicKey });
    expect(shortRead.manifest.duty.held < shortRead.manifest.duty.required).toBe(true);
    expect(metRead.manifest.duty.held >= metRead.manifest.duty.required).toBe(true);
    // The same shape either way, which is how a caller is stopped from reporting the difference as the
    // reader's finding: the comparison that decides it belongs to whoever holds the mapping `rev` names.
    expect(Object.keys(shortRead.outcome).sort()).toEqual(Object.keys(metRead.outcome).sort());
    expect(answered(() => verifyPack(signPack(short), { publicKey: KEY.publicKey }))).toBe('accepted');
    // The reader holds no registry of duty labels and invents none: the format declares the position a `tstr`
    // for the reason `receipt.cddl` gives its own scheme label, so it is read and nothing else.
    for (const art of ['19(1)', '19(2)', '26(6)', '']) {
      const bytes = signPack(manifestValue({ duty: { art, rev: SPAN_TO - 30, required: 3_600, held: SPAN_TO - BASE } }));
      expect(answered(() => decodePack(bytes)), `a duty label of "${art}" was refused`).toBe('accepted');
      expect(decodePack(bytes).manifest.duty.art).toBe(art);
    }
  });

  it('checks every original as the receipt it claims to be', () => {
    const run = chained(ENTRIES);
    // The bytes are the signed receipt, whole and unaltered, and they parse and verify under the key the
    // manifest's own header designates, which is the one the pack was just verified under.
    expect(() => verifyPack(signPack(manifestValue()), { publicKey: KEY.publicKey })).not.toThrow();
    const junk = manifestValue({ items: [{ id: 'receipt-0', iat: BASE, prev: run.items[0]!.prev, receipt: bytesOf('not a receipt at all') }, run.items[1]!, run.items[2]!] });
    const invalid = thrownBy(() => verifyPack(signPack(junk), { publicKey: KEY.publicKey })) as ReceiptError;
    expect(invalid.code).toBe('PACK_RECEIPT_INVALID');
    expect(invalid.message).toMatch(/receipt-0/u);
    // A receipt from another deployment, well signed by a key this pack does not name: the item's own bytes
    // verify against nothing the reader was handed, and the refusal says which item and with what answer.
    const foreign = manifestValue({ items: [run.items[0]!, { ...run.items[1]!, receipt: issueReceipt(receiptPayload(BASE + 1, 2), OTHER) }, run.items[2]!] });
    const foreignThrown = thrownBy(() => verifyPack(signPack(foreign), { publicKey: KEY.publicKey })) as ReceiptError;
    expect(foreignThrown.code).toBe('PACK_RECEIPT_INVALID');
    expect(foreignThrown.message).toMatch(/receipt-1 answers KID_MISMATCH/u);
    // One bit of one receipt: the chain would refuse that item too, and the originals are read first, so the
    // finding a caller hears is that this pack carries something other than the receipts it claims.
    const flipped = manifestValue({
      items: run.items.map((one, index) => (index === 1 ? { ...one, receipt: new Uint8Array(one.receipt.map((each) => each ^ 0x01)) } : one)),
    });
    expect(answered(() => verifyPack(signPack(flipped), { publicKey: KEY.publicKey }))).toBe('PACK_RECEIPT_INVALID');
    // A marked v2 receipt is still a receipt, and this reader is not where a version policy is decided. The
    // run is re-chained over those bytes, because a receipt is inside the hash the next one names.
    const markedRun = chained(ENTRIES, new Uint8Array(DIGEST_BYTES), KEY, (iat, nonce) => ({
      ...receiptPayload(iat, nonce),
      v: 2 as const,
      mk: { sch: 'none', d: sha256(new Uint8Array(0)) },
    }));
    const markedPack = manifestValue({ chain: { anchor: markedRun.anchor, head: markedRun.head }, items: markedRun.items });
    expect(answered(() => verifyPack(signPack(markedPack), { publicKey: KEY.publicKey }))).toBe('accepted');
    expect(verifyPack(signPack(markedPack), { publicKey: KEY.publicKey }).outcome.walked[0]!.receipt.payload.v).toBe(2);
    // Structural faults need no key, and an item whose original is junk is not a structural fault: a caller
    // with no key hears the manifest's own answers and nothing about the bytes inside the items.
    expect(answered(() => decodePack(signPack(junk)))).toBe('accepted');
  });

  it('binds an item to the stamp its own receipt attests, which is part of the walk', () => {
    // A receipt moved into a window it was never issued in, with the links repaired so the walk closes: the
    // store chains a receipt under the stamp it was handed, so the stamp and the receipt's own attestation are
    // two statements, and the equality of the two is the only thing that sees the move.
    const moved = { id: 'receipt-1', iat: BASE + 3_600, nonce: 2 };
    const run = chained([ENTRIES[0]!, moved, ENTRIES[2]!]);
    const end = BASE + 3_602;
    const restamped = manifestValue({
      at: end,
      span: { from: SPAN_FROM, to: end },
      chain: { anchor: run.anchor, head: run.head },
      duty: { art: '19(1)', rev: end - 30, required: 3_600, held: end - BASE },
      items: run.items,
    });
    expect(answered(() => verifyPack(signPack(restamped), { publicKey: KEY.publicKey }))).toBe('accepted');
    // The same three receipts with the middle item's stamp written as a value its own receipt does not carry,
    // and its successor's link recomputed over the moved stamp so that the run still closes at the head.
    const liar: PackItem[] = [run.items[0]!, { ...run.items[1]!, iat: run.items[1]!.iat + 1 }, { ...run.items[2]!, prev: framedDigest({ ...run.items[1]!, iat: run.items[1]!.iat + 1 }) }];
    const broken = thrownBy(() => verifyPack(signPack({ ...restamped, items: liar }), { publicKey: KEY.publicKey })) as ReceiptError;
    expect(broken.code).toBe('PACK_RECEIPT_STAMP_MISMATCH');
    expect(broken.message).toMatch(/receipt-1 is chained under/u);
    // And the equality is not the walk: with the stamps honest again the same three receipts close cleanly,
    // so the refusal above arrived at the one relation that case moved.
    expect(answered(() => verifyPack(signPack(restamped), { publicKey: KEY.publicKey }))).toBe('accepted');
  });

  it('leaves the map that carries no claim alone, in both directions', () => {
    const payload = encodeCanonical(manifestMap(manifestValue()));
    const empty = seal(payload, KEY);
    const junk = new Map<unknown, unknown>([
      ['note', 'a signature a reader was never asked to trust'],
      [encodedNumber(3, 'f64'), encodedNumber(2.5, 'f64')],
      ['span', { from: 0, to: 1 }],
      [bytesOf('whatever'), 7],
    ]);
    const withJunk = seal(payload, KEY, packHeader(KEY.kid), junk, encodeKeepingTypes);
    // The format declares this the one map a signer fills at will, and enforcing an emptiness would buy
    // strictness with no security content behind it. Refusing these bytes would be a rule it does not state.
    expect(() => verifyPack(withJunk, { publicKey: KEY.publicKey })).not.toThrow();
    expect(decodePack(withJunk).envelope.unprotected.size).toBe(4);
    expect(decodePack(empty).envelope.unprotected.size).toBe(0);
    // And nothing is read out of it: these two documents differ in nothing but the map outside the signature,
    // so every finding the reader reports is identical, including the window it answers for.
    const a = verifyPack(empty, { publicKey: KEY.publicKey });
    const b = verifyPack(withJunk, { publicKey: KEY.publicKey });
    expect(b.manifest).toEqual(a.manifest);
    expect(b.outcome).toEqual(a.outcome);
    expect(b.header).toEqual(a.header);
    // The junk survives the read as the bytes it was, which is the whole of what a reader may do with it.
    expect(b.envelope.unprotected.get('note')).toBe('a signature a reader was never asked to trust');
  });

  it('frames a chained record the way the specification states it and no other way', () => {
    const first = chained(ENTRIES).items[0]!;
    const honest = packRecordDigest(first);
    expect(toHex(honest)).toBe(toHex(sha256(framingInput(first))));
    expect(honest.length).toBe(DIGEST_BYTES);
    const input = framingInput(first);
    expect(input[0]).toBe(0);
    expect(input.length).toBe(1 + DIGEST_BYTES + 8 + 2 + bytesOf(first.id).length + first.receipt.length);
    for (const [name, moved] of [
      ['the predecessor', packRecordDigest({ ...first, prev: sha256(bytesOf('elsewhere')) })],
      ['the stamp', packRecordDigest({ ...first, iat: first.iat + 1 })],
      ['the name', packRecordDigest({ ...first, id: `${first.id}x` })],
      ['the bytes', packRecordDigest({ ...first, receipt: bytesOf('a different receipt') })],
    ] as Array<[string, Uint8Array]>) {
      expect(toHex(moved), `moving ${name} left the record digest alone`).not.toBe(toHex(honest));
    }
    // Big-endian and unsigned, which the stamp's eight bytes show: one past 2^32 moves the fourth byte from the
    // left and nothing after it.
    expect([...framingInput({ id: 'a', iat: 2 ** 32, prev: new Uint8Array(32), receipt: new Uint8Array(0) }).subarray(33, 41)]).toEqual([0, 0, 0, 1, 0, 0, 0, 0]);
    expect(() => packRecordDigest({ id: 'a', iat: 1, prev: new Uint8Array(31), receipt: new Uint8Array(0) })).toThrow(/predecessor of 31 bytes/u);
    expect(() => packRecordDigest({ id: '', iat: 1, prev: new Uint8Array(32), receipt: new Uint8Array(0) })).toThrow(/an id of 0 bytes/u);
  });

  it('reproduces the digest of every record image the estate published', () => {
    // Where a sentence of the CDDL and these images disagree about a frame, the images are the authority, and
    // this is the case that settles it for the reader's own digest function: the published predecessor, stamp,
    // id and payload bytes go in, and the `digestHex` the store wrote comes out.
    const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8')) as {
      layout: { record: string; kinds: { receipt: number; trim: number }; digestInput: string };
      scenarios: Array<{ name: string; records: Array<Record<string, unknown>> }>;
    };
    expect(vectors.layout.record).toBe('len:u32 || kind:u8 || prev:32 || iat:u64 || idLen:u16 || id || payload || digest:32');
    let checked = 0;
    for (const scenario of vectors.scenarios) {
      for (const record of scenario.records) {
        // A trim carries no receipt, so it is never a pack item and its empty id belongs to no frame this
        // reader rebuilds. The count below is what keeps that skip from becoming a silent one.
        if (Number(record.kind) !== vectors.layout.kinds.receipt) continue;
        const item: FrameInput = {
          id: String(record.id),
          iat: Number(record.iat),
          prev: fromHex(String(record.prevHex)),
          receipt: fromBase64Url(String(record.payloadBase64Url), 'PACK_MALFORMED_CBOR'),
        };
        expect(toHex(packRecordDigest(item)), `${scenario.name} record at offset ${String(record.offset)}`).toBe(String(record.digestHex));
        const frame = framingInput(item);
        const view = new DataView(frame.buffer, frame.byteOffset);
        expect([view.getUint16(41), bytesOf(item.id).length], `${scenario.name} states an id length the frame does not carry`).toEqual([bytesOf(item.id).length, bytesOf(item.id).length]);
        checked += 1;
      }
    }
    expect(checked, 'the published images carry no receipt record to check the framing against').toBeGreaterThan(0);
  });

  it('refuses a signature over bytes the issuer did not choose', () => {
    const bytes = signPack(manifestValue());
    const flipped = new Uint8Array(bytes);
    const at = flipped.length - 70;
    flipped[at] = (flipped[at] ?? 0) ^ 0x01;
    // The signature is checked before the manifest is read, so a mutated byte is a refusal about the bytes and
    // never a structural answer the document did not earn.
    expect(codeOf(() => verifyPack(flipped, { publicKey: KEY.publicKey }))).toBe('INVALID_SIGNATURE');
    expect(codeOf(() => verifyPack(bytes, { publicKey: OTHER.publicKey }))).toBe('PACK_KID_MISMATCH');
    // The framing the signature covers is the whole contract of a COSE document, and it is the receipt's own
    // framing around this container's payload: a reimplementer comparing two readers starts from these bytes.
    const [prot, , payload] = elementsOf(bytes);
    expect(toHex(packSigStructure(prot as Uint8Array, payload as Uint8Array))).toBe(toHex(encodeCanonical(['Signature1', prot, new Uint8Array(0), payload])));
    expect(toHex(packSigStructure(prot as Uint8Array, payload as Uint8Array, bytesOf('aad')))).not.toBe(toHex(packSigStructure(prot as Uint8Array, payload as Uint8Array)));
  });

  it('refuses an item the reader cannot identify, which is a name and not a link', () => {
    const run = chained(ENTRIES);
    const collided = manifestValue({ items: [...run.items, { ...run.items[1]!, id: run.items[0]!.id }] });
    // Chained honestly is impossible here by construction, and that is the point: the name sits inside the
    // hash, so both spellings of it hash perfectly and nothing about a chain says two items share a name. The
    // links order a pack and the name identifies it, and a refusal that reports an item by name would otherwise
    // mean whichever of the two a reader met first.
    expect(codeOf(() => decodePack(signPack(collided)))).toBe('PACK_DUPLICATE_ID');
    expect(codeOf(() => verifyPack(signPack(collided), { publicKey: KEY.publicKey }))).toBe('PACK_DUPLICATE_ID');
  });

  it('is named by the section of the specification it implements, and says no more than it does', () => {
    // Section 5.2 states the framing and the walk, and this is the case that ties its prose about this
    // repository to the code that prose names: the file it names is there, and the claims it makes about what
    // the reader answers are claims a refusal or an absence in the source can be asked about.
    const spec = readFileSync(specPath, 'utf8');
    const readerSource = readFileSync(readerSourcePath, 'utf8');
    const start = spec.indexOf('### 5.2 Record framing and chain recomputation');
    const end = spec.indexOf('### 5.3', start);
    expect(start, 'section 5.2 is not in the specification').toBeGreaterThanOrEqual(0);
    const body = spec.slice(start, end < 0 ? spec.length : end).replace(/\s+/gu, ' ');
    const paragraph = 'What this repository reads of a pack.';
    expect(body.split(paragraph).length - 1, 'the section names this reader, once').toBe(1);
    expect(existsSync(readerSourcePath), 'the section names a file that is not there').toBe(true);
    for (const named of ['packages/receipt/src/pack.ts', 'packages/receipt/pack.cddl', PACK_CONTENT_TYPE]) {
      expect(body, `the section does not name ${named}`).toContain(named);
    }
    // The resolution rule, held to the code it describes rather than to this file's memory of it. The section
    // says each item verifies under the key its own header names, that a resolver is asked once per kid, and
    // that a pinned key still answers the whole container; the reader that does those three is read back here,
    // so either side moving alone makes the prose and the code disagree, which is the failure this case exists
    // to catch.
    expect(body, 'the section does not say which key an item verifies under').toContain(
      "verifies each item's receipt as a receipt, under the key that item's own header names",
    );
    expect(body, 'the section does not say what a resolver is asked for').toContain(
      'a resolver is asked once for each kid the documents name',
    );
    expect(readerSource, 'the reader no longer forwards one designation to each item').toMatch(/verifyReceipt\(item\.receipt, options\)/u);
    expect(readerSource, 'the reader resolves the envelope key after checking its signature').toMatch(
      /const publicKey = envelopeKey\(envelope\.header\.kid, options\);[\s\S]*?!ed25519\.verify/u,
    );
    // What the section must still refuse to claim. A key handed to this reader is not authenticated by it, the
    // keys a rotation-spanning pack needs are the ones section 5's step 2 already names for a receipt, and the
    // one-key sentence this pass retired must not come back as prose.
    expect(body, 'the section overstates what resolution buys').toContain('It authenticates no key.');
    expect(body, 'the section does not say what a caller has to supply').toContain(
      'pinned in the policy AND declared by the deployment manifest',
    );
    expect(body, 'the section still describes one key answering every document').not.toMatch(/under the key the manifest's own header designates/u);
    // The two findings the paragraph says are kept apart, and the window comparison it leaves to the reader: a
    // run can close cleanly over fewer receipts than the window it states, and only the pair of the two fields
    // says so. A caller printing the count alone would be reporting a window it was never shown complete.
    const honest = manifestValue();
    const shorter = chained([ENTRIES[0]!, ENTRIES[2]!]);
    const shortened = manifestValue({ chain: { anchor: shorter.anchor, head: shorter.head }, items: shorter.items });
    const walked = verifyPack(signPack(shortened), { publicKey: KEY.publicKey });
    expect(walked.outcome.walked.map((one) => one.item.id)).toEqual(['receipt-0', 'receipt-2']);
    expect(walked.outcome.span).toEqual(honest.span);
    expect(walked.outcome.walked.length).not.toBe(honest.items.length);
    // What the paragraph states as still absent: nothing assembles a pack. The reader publishes the bytes a
    // signature covers and the framing a digest is taken over, and exports no writer, so the sentence cannot
    // become false quietly from this package.
    const surface = readFileSync(fileURLToPath(new URL('../src/index.ts', import.meta.url)), 'utf8');
    expect(surface).toMatch(/from '\.\/pack\.js'/u);
    for (const [name, source] of [['pack.ts', readerSource], ['index.ts', surface]] as const) {
      expect(source, `${name} exports a writer for a format that states it has none`).not.toMatch(
        /^export (?:async )?function (?:sign|seal|encode|build)\w*/mu,
      );
    }
    expect(
      spec,
      'the specification still claims this repository reads no pack, which the paragraph above refutes',
    ).not.toMatch(/nothing (?:here|in this repository) reads a pack/iu);
  });
});

/**
 * The key designation `verifyPack` offers, which is the seam `verifyReceipt` has always offered and the reason a
 * pack whose span crosses a rotation is readable at all: a deployment rotates its signing key, the manifest's
 * `keys[]` retains the superseded epoch, and a caller that already adjudicates epochs for one receipt can hand
 * this reader the same set.
 *
 * Every case runs through the reader's public entry point, and the two-epoch pack is assembled here out of the
 * package's own receipt writer and this file's own framing rather than mocked, because what is under test is
 * which key each document was checked against. A resolver records the kids it was asked for, and the resolver
 * that reports its own consultation is how the orderings are proved: an answer that arrived after a key had
 * been reached would fail as that exception rather than as a code.
 */
describe('the pack verifier resolves keys the way the receipt verifier does', () => {
  const good = signPack(manifestValue());
  const both = (): PackVerifyOptions => ({ resolveKey: keySet([KEY, OTHER]).resolveKey });

  it('refuses a verification it was given no key for, and says that it was the call', () => {
    // The fault is in the call, so it is answered before a byte is read: a caller that handed over neither is
    // not being told anything about the document it was holding, and answering a document question instead
    // would send an operator to the pack rather than to their own configuration.
    const unconfigured = thrownBy(() => verifyPack(good, {})) as ReceiptError;
    expect(unconfigured.code).toBe('PACK_UNKNOWN_KEY');
    expect(unconfigured.message).toMatch(/no publicKey or resolveKey provided/u);
    expect(codeOf(() => verifyPack(new Uint8Array([0xff]), {}))).toBe('PACK_UNKNOWN_KEY');
    expect(codeOf(() => verifyPack(good, { publicKey: undefined, resolveKey: undefined }))).toBe('PACK_UNKNOWN_KEY');
    // Either one of the two designates, and a call that hands over both is answered by the pinned key, which is
    // the designation that says which single key the caller means.
    expect(answered(() => verifyPack(good, { publicKey: KEY.publicKey }))).toBe('accepted');
    expect(answered(() => verifyPack(good, { resolveKey: keySet([KEY]).resolveKey }))).toBe('accepted');
    expect(answered(() => verifyPack(good, { publicKey: KEY.publicKey, resolveKey: neverAsked() }))).toBe('accepted');
  });

  it('resolves the envelope key before it checks the signature that key is asked to carry', () => {
    // A pinned key keeps the answer it has always given, in the same words and with both kids quoted, which is
    // the report that sends an operator to the configuration rather than to the bytes.
    const pinned = thrownBy(() => verifyPack(good, { publicKey: OTHER.publicKey })) as ReceiptError;
    expect(pinned.code).toBe('PACK_KID_MISMATCH');
    expect(pinned.message).toMatch(/^the key handed to the reader does not match the kid the pack names: header kid=[0-9a-f]{64} key kid=[0-9a-f]{64}$/u);
    // A resolver is asked for the kid the header carries, which is the document's own choice, and the envelope
    // verifies under whatever that answers with.
    const set = keySet([KEY, OTHER]);
    expect(answered(() => verifyPack(good, { resolveKey: set.resolveKey }))).toBe('accepted');
    expect(set.asked[0], 'the resolver was not asked for the kid the header names').toBe(toHex(KEY.kid));
    // A kid it holds nothing for is refused rather than guessed at with some other key the caller owns, and the
    // refusal quotes the kid that went unanswered, which is the one fact the caller needs in order to retain it.
    const missing = thrownBy(() => verifyPack(good, { resolveKey: keySet([]).resolveKey })) as ReceiptError;
    expect(missing.code).toBe('PACK_UNKNOWN_KEY');
    expect(missing.message).toContain(`header kid=${toHex(KEY.kid)}`);
    // A key that names another kid is the same disagreement a pinned key is, and answers with its code rather
    // than letting the signature check report a wrong key as an edited document.
    expect(codeOf(() => verifyPack(good, { resolveKey: () => OTHER.publicKey }))).toBe('PACK_KID_MISMATCH');
    // And resolution precedes the signature itself: these bytes carry one flipped bit of the envelope's
    // signature, so a reader with no key for the kid they name says that, and only a reader holding the key
    // reaches an answer about the mutation.
    const tampered = new Uint8Array(good);
    tampered[tampered.length - 70] = (tampered[tampered.length - 70] ?? 0) ^ 0x01;
    expect(codeOf(() => verifyPack(tampered, { resolveKey: () => undefined }))).toBe('PACK_UNKNOWN_KEY');
    expect(codeOf(() => verifyPack(tampered, { publicKey: KEY.publicKey }))).toBe('INVALID_SIGNATURE');
  });

  it('refuses a document that is not a pack before any resolver is consulted', () => {
    // The ordering is the whole reason four signed containers carry four content types, and a resolver that
    // throws is the only proof of it that cannot be read the wrong way: had the reader reached a caller's key
    // set for any document below, the case would fail with that exception instead of with a code.
    const payload = encodeCanonical(manifestMap(manifestValue()));
    for (const [name, contentType] of [
      ['a receipt', 'ashaveri/receipt'],
      ['an export', EXPORT_CONTENT_TYPE],
      ['a deployment manifest', 'ashaveri/deployment-manifest'],
    ] as const) {
      const thrown = thrownBy(() => verifyPack(seal(payload, KEY, packHeader(KEY.kid, contentType)), { resolveKey: neverAsked() })) as ReceiptError;
      expect(thrown, `${name} was read as a pack`).toBeInstanceOf(ReceiptError);
      expect(thrown.code, `${name} answered another code`).toBe('PACK_BAD_HEADER');
      expect(thrown.message, `${name} did not name its content type`).toContain(`typ=${contentType}`);
    }
    // The same three through the bytes a reader would actually meet: a real receipt from this package's own
    // writer and a real sealed deployment manifest, each carrying its own type.
    expect(codeOf(() => verifyPack(issueReceipt(receiptPayload(BASE, 1), KEY), { resolveKey: neverAsked() }))).toBe('PACK_BAD_HEADER');
    expect(codeOf(() => verifyPack(sealDeploymentManifest(bytesOf('{"v":1}'), KEY), { resolveKey: neverAsked() }))).toBe('PACK_BAD_HEADER');
    // Nothing else is consulted either: a header the format does not accept is refused without a key, so a
    // resolver is never the thing that decides what a caller hears about a document it should not have opened.
    const untyped = packHeader(KEY.kid);
    untyped.delete(COSE_HEADER_CONTENT_TYPE);
    expect(codeOf(() => verifyPack(seal(payload, KEY, untyped), { resolveKey: neverAsked() }))).toBe('PACK_BAD_HEADER');
  });

  it('verifies a pack whose span crosses a key rotation against the keys the caller retained', () => {
    const bytes = signPack(rotatedManifest(2), KEY);
    const retained = keySet([KEY, OTHER]);
    const read = verifyPack(bytes, { resolveKey: retained.resolveKey });
    // The same run, in the order the links put it, with the envelope verified under the key that is current.
    expect(read.outcome.walked.map((one) => one.item.id)).toEqual(['receipt-0', 'receipt-1', 'receipt-2']);
    expect(toHex(read.header.kid)).toBe(toHex(KEY.kid));
    // Each item was checked against the key its own header names, and two of the three are not the key the
    // envelope answered to. That is the rotation, and it is the pack this reader could not verify at all.
    expect(read.outcome.walked.map((one) => toHex(one.receipt.header.kid))).toEqual([toHex(OTHER.kid), toHex(OTHER.kid), toHex(KEY.kid)]);
    for (const one of read.outcome.walked) {
      expect(one.receipt.payload.iat).toBe(one.item.iat);
    }
    // Asked once for the envelope and once for each item, in the order the originals were read, and never for a
    // kid this document does not name.
    expect(retained.asked).toEqual([toHex(KEY.kid), toHex(OTHER.kid), toHex(OTHER.kid), toHex(KEY.kid)]);
    // A rotation of one receipt rather than two is the same case with the line moved, and a pack that never
    // rotated reads under either designation, which is the single-key path keeping its present answer.
    expect(answered(() => verifyPack(signPack(rotatedManifest(1), KEY), both()))).toBe('accepted');
    expect(answered(() => verifyPack(good, { publicKey: KEY.publicKey }))).toBe('accepted');
    // One pinned key on the rotation-spanning bytes is the answer this reader gave before it resolved anything,
    // and it names the item it could not verify rather than the pack: the old behaviour, preserved.
    const single = thrownBy(() => verifyPack(bytes, { publicKey: KEY.publicKey })) as ReceiptError;
    expect(single.code).toBe('PACK_RECEIPT_INVALID');
    expect(single.message).toMatch(/receipt-0 answers KID_MISMATCH/u);
    // Reading the same pack from the other side of the rotation does not work either, and does not pretend to:
    // the envelope names the current key, and that disagreement is answered at the envelope, where the reader
    // is refused before any of the receipts it could have read is reported on.
    const retiredOnly = thrownBy(() => verifyPack(bytes, { resolveKey: keySet([OTHER]).resolveKey })) as ReceiptError;
    expect(retiredOnly.code).toBe('PACK_UNKNOWN_KEY');
    expect(retiredOnly.message).toContain(`header kid=${toHex(KEY.kid)}`);
    expect(codeOf(() => verifyPack(bytes, { publicKey: OTHER.publicKey }))).toBe('PACK_KID_MISMATCH');
  });

  it('keeps an item key the caller does not hold apart from a refusal about an original', () => {
    const bytes = signPack(rotatedManifest(2), KEY);
    // The retained set reaches the current epoch and not the retired one. The envelope verifies and the walk
    // would close, and what stopped the reader is a kid nobody answered, which is a caller holding too few keys
    // and not a pack carrying something other than the receipts it claims.
    const partial = thrownBy(() => verifyPack(bytes, { resolveKey: keySet([KEY]).resolveKey })) as ReceiptError;
    expect(partial.code).toBe('PACK_UNKNOWN_KEY');
    expect(partial.code).not.toBe('PACK_RECEIPT_INVALID');
    expect(partial.message).toMatch(/receipt-0 names a kid the reader was given no key for/u);
    // The three faults a caller meets on an item, kept apart because the actions are three: go and retain the
    // key the manifest names, refuse this pack, and refuse this pack for one named reason.
    const misled = new Map<string, Uint8Array>([
      [toHex(KEY.kid), KEY.publicKey],
      [toHex(OTHER.kid), signingKeyFromSeed(new Uint8Array(32).fill(21)).publicKey],
    ]);
    const wrongKey = thrownBy(() => verifyPack(bytes, { resolveKey: (kid) => misled.get(toHex(kid)) })) as ReceiptError;
    expect(wrongKey.code).toBe('PACK_RECEIPT_INVALID');
    expect(wrongKey.message).toMatch(/receipt-0 answers KID_MISMATCH/u);
    const run = chained(ENTRIES);
    const junk = manifestValue({
      items: [{ id: 'receipt-0', iat: BASE, prev: run.items[0]!.prev, receipt: bytesOf('not a receipt at all') }, ...run.items.slice(1)],
    });
    const edited = thrownBy(() => verifyPack(signPack(junk, KEY), { resolveKey: keySet([KEY]).resolveKey })) as ReceiptError;
    expect(edited.code).toBe('PACK_RECEIPT_INVALID');
    expect(edited.message).toMatch(/receipt-0 answers/u);
  });

  it('leaves the stamp equality and both halves of the chain check where they were', () => {
    const rotated = rotatedManifest(2);
    // An item chained under a stamp its own receipt does not attest, with its successor's link recomputed so
    // the run still closes at the signed head, is refused by the equality rather than by the walk, under a
    // resolver exactly as under one pinned key.
    const lied: PackItem[] = rotated.items.map((one, index) => {
      if (index === 1) return { ...one, iat: one.iat + 1 };
      if (index === 2) return { ...one, prev: framedDigest({ ...rotated.items[1]!, iat: rotated.items[1]!.iat + 1 }) };
      return one;
    });
    const stamp = thrownBy(() => verifyPack(signPack({ ...rotated, items: lied }, KEY), both())) as ReceiptError;
    expect(stamp.code).toBe('PACK_RECEIPT_STAMP_MISMATCH');
    expect(stamp.message).toMatch(/receipt-1 is chained under/u);
    // The first half of the walk: a record lifted out of the middle stops the run short of the head.
    const gap = thrownBy(() => verifyPack(signPack({ ...rotated, items: [rotated.items[0]!, rotated.items[2]!] }, KEY), both())) as ReceiptError;
    expect(gap.code).toBe('PACK_CHAIN_BROKEN');
    // The second half, which is the one with eyes for a receipt parked beside a span it is not part of.
    const parked: PackItem = { id: 'parked', iat: BASE + 1, prev: sha256(bytesOf('another chain entirely')), receipt: issueReceipt(receiptPayload(BASE + 1, 9), OTHER) };
    const unreached = thrownBy(() => verifyPack(signPack({ ...rotated, items: [...rotated.items, parked] }, KEY), both())) as ReceiptError;
    expect(unreached.code).toBe('PACK_ITEM_UNREACHED');
    expect(unreached.message).toMatch(/parked/u);
    // The control, which is the same three items whole and the same key set.
    expect(answered(() => verifyPack(signPack(rotated, KEY), both()))).toBe('accepted');
  });
});
