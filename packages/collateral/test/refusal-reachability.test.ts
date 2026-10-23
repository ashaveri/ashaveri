import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { sha256, sha384 } from '@noble/hashes/sha2.js';
import {
  foreignKey,
  qeIdentity,
  secondsOf,
  servedAnswer,
  servedChainOf,
  tcbInfo,
  testVendor,
  type TestVendor,
} from '@ashaveri/fixtures';
import {
  AMD_KDS,
  INTEL_PCK_CRL,
  INTEL_QE_IDENTITY,
  INTEL_TCB_INFO,
  NVIDIA_OCSP,
  NVIDIA_RIM,
  ORIGIN_DECLARATIONS,
  SERVED_ORIGINS,
  appraiseCollateral,
  appraiseOcspResponse,
  appraisePckCrl,
  appraiseVcekChain,
  collateralRefusals,
  declarationFor,
  fetchFromOrigin,
  readRimManifest,
  requestUrl,
  type CollateralErrorCode,
  type CollateralQuery,
  type CollateralRefusal,
  type CollateralTransport,
  type OcspQuery,
  type PckCrlQuery,
  type ReadCollateralOrigin,
  type ReadDocumentOrigin,
  type RimReadOutcome,
  type VcekChainQuery,
} from '../src/index.js';
import { utf8 } from '../src/bytes.js';
import { ocspDevice, writeOcspResponse, type OcspInput } from './ocsp-writer.js';
import { writeRimWrapper } from './rim-writer.js';
import { manifestBytes, rimChain, rimManifest, wrap } from './rim-document-writer.js';
import { amdAsk, amdChain, amdRoot, amdVcek, hwidHex, hwidOf, secondsOf as writerSeconds } from './kds-writer.js';
import { writeCrl } from './crl-writer.js';

/**
 * The reachability grid `docs/error-codes.md` carries, held to the package by running it.
 *
 * Shape checks cannot tell a true sentence from a well-formed one, so this suite reads no sentence: it reads the
 * grid's four columns, and for every cell it either produces the answer or reads the fact. A `yes` is worth
 * nothing unless a public entry point returns that code for an answer this file builds, so each `yes` cell names
 * the scenario that produces it and the run asserts the code the answer arrives with. A `no` is worth nothing
 * unless a member of the origin's own declaration carries it, so each `no` cell names the fact and the run reads
 * it back out of the declaration: a declaration that gained the member a `no` rests on turns that cell red
 * rather than leaving the sentence standing. Each fact is chosen by the code a cell cites and narrowed by the
 * origin citing it, so a `no` written for a pair no fact covers is named there rather than carried by a fact
 * meant for a neighbour. Every cited symbol is checked to be declared in the file the cell names, which is what
 * makes a rename in the source a failure here rather than a stale line in a document.
 *
 * The grid is the origins `SERVED_ORIGINS` names crossed with the codes `collateralRefusals()` states, in those
 * orders. An origin or a code added to the package has no cell here, so the document's table and this file's
 * cells both refuse until somebody decides which answer reaches it.
 */

const HEADER = '| Origin | Refusal | Reached | Where it is decided |';

/** The paths a grid cell spells, keyed by the short name this file uses for them. */
const FILES = {
  amd: 'packages/collateral/src/amd-kds.ts',
  classify: 'packages/collateral/src/classify.ts',
  crl: 'packages/collateral/src/crl.ts',
  fetch: 'packages/collateral/src/fetch.ts',
  ocsp: 'packages/collateral/src/ocsp.ts',
  origin: 'packages/collateral/src/intel-origin.ts',
  read: 'packages/collateral/src/read.ts',
  rim: 'packages/collateral/src/rim.ts',
  served: 'packages/collateral/src/served.ts',
} as const;

type FileKey = keyof typeof FILES;
type Reached = 'yes' | 'no' | 'not exercised';
/** One cell as the grid carries it: the answer, where it is decided, and what the cell rests on. */
type CellSpec = readonly [Reached, FileKey, string, string];

/** Which answer each origin reaches, and which declaration fact carries each answer it does not. */
const CELLS: Record<ReadCollateralOrigin, Record<CollateralErrorCode, CellSpec>> = {
  'intel-tcb-info': {
    COLLATERAL_INPUT_MISSING: ['yes', 'classify', 'askedButNotGiven', 'an appraisal that states no instant to appraise at'],
    COLLATERAL_ANCHOR_NOT_PINNED: ['yes', 'read', 'parsePinned', 'a served pair weighed under bytes pinned as a root that hold no certificate'],
    COLLATERAL_ORIGIN_UNSUPPORTED: ['no', 'origin', 'declarationFor', 'the declaration names a reader, so no unread-origin arm is reached'],
    COLLATERAL_ORIGIN_UNREACHABLE: ['yes', 'fetch', 'fetchFromOrigin', 'a transport that throws on the way to the declared host'],
    COLLATERAL_ORIGIN_REFUSED: ['yes', 'fetch', 'fetchFromOrigin', 'a 403 answered in place of a document'],
    COLLATERAL_BLOB_UNREADABLE: ['yes', 'read', 'readSignedCollateral', 'a served body that arrived without the header carrying its chain'],
    COLLATERAL_SIGNATURE_UNVERIFIED: ['yes', 'served', 'readServedCollateral', 'a wrapper signed over its own span by a key the presented chain did not issue'],
    COLLATERAL_IDENTITY_MISMATCH: ['yes', 'read', 'readCpuType', 'a signed document whose fmspc is not the one the query asked about'],
    COLLATERAL_TCB_LEVEL_UNLISTED: ['yes', 'read', 'unlistedLevel', 'a level the signed list carries no rung for'],
    COLLATERAL_STATUS_UNSUPPORTED: ['yes', 'classify', 'classify', 'a vendor word in neither the trusted list nor the revoked one'],
    COLLATERAL_WINDOW_CLOSED: ['yes', 'classify', 'classify', 'a fetched document appraised after its own nextUpdate'],
    COLLATERAL_NOT_OBSERVED: ['yes', 'classify', 'classify', 'a body and chain kept from an earlier run, with no origin asked'],
    COLLATERAL_RETAINED_CHAIN_MISMATCH: ['yes', 'classify', 'observe', 'a retained chain beside a stated digest it does not hash to'],
    COLLATERAL_REVOKED_BY_VENDOR: ['yes', 'classify', 'classify', 'a level the vendor signed OutOfDate'],
  },
  'intel-qe-identity': {
    COLLATERAL_INPUT_MISSING: ['yes', 'classify', 'askedButNotGiven', 'an appraisal that states no instant to appraise at'],
    COLLATERAL_ANCHOR_NOT_PINNED: ['yes', 'read', 'parsePinned', 'a served pair weighed under bytes pinned as a root that hold no certificate'],
    COLLATERAL_ORIGIN_UNSUPPORTED: ['no', 'origin', 'declarationFor', 'the declaration names a reader, so no unread-origin arm is reached'],
    COLLATERAL_ORIGIN_UNREACHABLE: ['yes', 'fetch', 'fetchFromOrigin', 'a transport that throws on the way to the declared host'],
    COLLATERAL_ORIGIN_REFUSED: ['yes', 'fetch', 'fetchFromOrigin', 'a 403 answered in place of a document'],
    COLLATERAL_BLOB_UNREADABLE: ['yes', 'read', 'readSignedCollateral', 'a served body that arrived without the header carrying its chain'],
    COLLATERAL_SIGNATURE_UNVERIFIED: ['yes', 'served', 'readServedCollateral', 'a wrapper signed over its own span by a key the presented chain did not issue'],
    COLLATERAL_IDENTITY_MISMATCH: ['no', 'origin', 'INTEL_QE_IDENTITY', 'identity.cpuTypeMember is null, so the reader has no identity to compare'],
    COLLATERAL_TCB_LEVEL_UNLISTED: ['yes', 'read', 'unlistedLevel', 'a level the signed list carries no rung for'],
    COLLATERAL_STATUS_UNSUPPORTED: ['yes', 'classify', 'classify', 'a vendor word in neither the trusted list nor the revoked one'],
    COLLATERAL_WINDOW_CLOSED: ['yes', 'classify', 'classify', 'a fetched document appraised after its own nextUpdate'],
    COLLATERAL_NOT_OBSERVED: ['yes', 'classify', 'classify', 'a body and chain kept from an earlier run, with no origin asked'],
    COLLATERAL_RETAINED_CHAIN_MISMATCH: ['yes', 'classify', 'observe', 'a retained chain beside a stated digest it does not hash to'],
    COLLATERAL_REVOKED_BY_VENDOR: ['yes', 'classify', 'classify', 'a level the vendor signed OutOfDate'],
  },
  'intel-pck-crl': {
    COLLATERAL_INPUT_MISSING: ['yes', 'classify', 'askedButNotGivenCrl', 'a serial question that names no certificate serial'],
    COLLATERAL_ANCHOR_NOT_PINNED: ['yes', 'classify', 'askedButNotGivenCrl', 'a verdict asked with no root in hand'],
    COLLATERAL_ORIGIN_UNSUPPORTED: ['no', 'origin', 'declarationFor', 'the declaration names a reader, so no unread-origin arm is reached'],
    COLLATERAL_ORIGIN_UNREACHABLE: ['yes', 'fetch', 'fetchFromOrigin', 'a transport that throws on the way to the declared host'],
    COLLATERAL_ORIGIN_REFUSED: ['yes', 'fetch', 'fetchFromOrigin', 'a 403 answered in place of a list'],
    COLLATERAL_BLOB_UNREADABLE: ['yes', 'crl', 'readPckCrl', 'a list that states no nextUpdate, so it bounds no window'],
    COLLATERAL_SIGNATURE_UNVERIFIED: ['yes', 'crl', 'readPckCrl', 'a well-formed list signed with a key the presented chain did not issue'],
    COLLATERAL_IDENTITY_MISMATCH: ['yes', 'crl', 'readPckCrl', 'the platform authority list asked about as the processor scope'],
    COLLATERAL_TCB_LEVEL_UNLISTED: ['no', 'origin', 'INTEL_PCK_CRL', 'the declaration states serialMember and no identity block, so no level is read'],
    COLLATERAL_STATUS_UNSUPPORTED: ['yes', 'classify', 'classifyRevocation', 'an entry whose reason is removeFromCRL'],
    COLLATERAL_WINDOW_CLOSED: ['yes', 'classify', 'classifyRevocation', 'a fetched list appraised after its nextUpdate and not naming the serial'],
    COLLATERAL_NOT_OBSERVED: ['yes', 'classify', 'classifyRevocation', 'a list and chain kept from an earlier run, with no origin asked'],
    COLLATERAL_RETAINED_CHAIN_MISMATCH: ['yes', 'classify', 'observe', 'a retained chain beside a stated digest it does not hash to'],
    COLLATERAL_REVOKED_BY_VENDOR: ['yes', 'classify', 'classifyRevocation', 'a list naming the serial the question asked about'],
  },
  'amd-kds': {
    COLLATERAL_INPUT_MISSING: ['yes', 'classify', 'askedButNotGivenChain', 'a chip question that states no instant to appraise at'],
    COLLATERAL_ANCHOR_NOT_PINNED: ['yes', 'classify', 'askedButNotGivenChain', 'a chip question asked with no root in hand'],
    COLLATERAL_ORIGIN_UNSUPPORTED: ['no', 'origin', 'declarationFor', 'the declaration names a reader, so no unread-origin arm is reached'],
    COLLATERAL_ORIGIN_UNREACHABLE: ['yes', 'fetch', 'fetchFromOrigin', 'a transport that throws on the way to the declared host'],
    COLLATERAL_ORIGIN_REFUSED: ['yes', 'fetch', 'fetchFromOrigin', 'a 404 answered at the chain route beside a whole certificate'],
    COLLATERAL_BLOB_UNREADABLE: ['yes', 'amd', 'readVcekChain', 'a chain answer holding no certificate that parses'],
    COLLATERAL_SIGNATURE_UNVERIFIED: ['yes', 'amd', 'believe', 'a pair weighed at a moment its certificates do not stand at'],
    COLLATERAL_IDENTITY_MISMATCH: ['yes', 'amd', 'readIdentity', 'a certificate for another chip asked about as this one'],
    COLLATERAL_TCB_LEVEL_UNLISTED: ['no', 'origin', 'AMD_KDS', 'the declaration names the chip members and states no level roster'],
    COLLATERAL_STATUS_UNSUPPORTED: ['no', 'origin', 'AMD_KDS', 'the declaration states no vendor vocabulary, so no word can fall outside it'],
    COLLATERAL_WINDOW_CLOSED: ['no', 'origin', 'AMD_KDS', 'the declaration states no window members, so no signed window of a level is weighed'],
    COLLATERAL_NOT_OBSERVED: ['yes', 'classify', 'classifyChain', 'a pair kept from an earlier run, with neither route asked'],
    COLLATERAL_RETAINED_CHAIN_MISMATCH: ['yes', 'classify', 'observe', 'a retained chain beside a stated digest it does not hash to'],
    COLLATERAL_REVOKED_BY_VENDOR: ['no', 'origin', 'AMD_KDS', 'neither route answers a revocation shape and the declaration states no vendor word'],
  },
  ocsp: {
    COLLATERAL_INPUT_MISSING: ['yes', 'classify', 'askedButNotGivenOcsp', 'a certificate question that states no instant to appraise at'],
    COLLATERAL_ANCHOR_NOT_PINNED: ['yes', 'read', 'parsePinned', 'an answer weighed under bytes pinned as a root that hold no certificate'],
    COLLATERAL_ORIGIN_UNSUPPORTED: ['no', 'origin', 'declarationFor', 'the declaration names a reader, so no unread-origin arm is reached'],
    COLLATERAL_ORIGIN_UNREACHABLE: ['yes', 'fetch', 'fetchFromOrigin', 'a transport that throws on the way to the declared host'],
    COLLATERAL_ORIGIN_REFUSED: ['yes', 'ocsp', 'readOcspResponse', 'a responder status of tryLater in place of a signed statement'],
    COLLATERAL_BLOB_UNREADABLE: ['yes', 'ocsp', 'readOcspResponse', 'an answer that states no nextUpdate, so it bounds no window'],
    COLLATERAL_SIGNATURE_UNVERIFIED: ['yes', 'ocsp', 'readOcspResponse', 'an answer signed with a key the issuer the question names did not issue'],
    COLLATERAL_IDENTITY_MISMATCH: ['yes', 'ocsp', 'bindCertId', 'a CertID about another certificate than the one the question asked about'],
    COLLATERAL_TCB_LEVEL_UNLISTED: ['no', 'origin', 'NVIDIA_OCSP', 'the declaration names the certificate members and states no level roster'],
    COLLATERAL_STATUS_UNSUPPORTED: ['yes', 'classify', 'classifyOcsp', 'a standing of unknown, which states no revocation and no good standing'],
    COLLATERAL_WINDOW_CLOSED: ['yes', 'classify', 'classifyOcsp', 'a fetched answer appraised after its own nextUpdate'],
    COLLATERAL_NOT_OBSERVED: ['yes', 'classify', 'classifyOcsp', 'an answer kept from an earlier run, with the responder unasked'],
    COLLATERAL_RETAINED_CHAIN_MISMATCH: ['yes', 'classify', 'observe', 'a retained chain beside a stated digest it does not hash to'],
    COLLATERAL_REVOKED_BY_VENDOR: ['yes', 'classify', 'classifyOcsp', 'an answer reading revoked for the certificate asked about'],
  },
  /**
   * The RIM row is the reach of the reader that weighs a wrapper and, for the shape whose profile it states, the
   * manifest inside that wrapper. Four codes belong to a verdict this origin reaches never and are carried by the
   * members the declaration states none of: no window, no identity block, no cache rule, no revocation shape on
   * its route. The rest are the failures of an answer this path reads, produced by `readRimManifest`,
   * `requestUrl` and `fetchFromOrigin`.
   */
  'nvidia-rim': {
    COLLATERAL_INPUT_MISSING: ['yes', 'origin', 'declaredUrl', 'a RIM route whose id placeholder the question leaves empty'],
    COLLATERAL_ANCHOR_NOT_PINNED: ['yes', 'rim', 'walkToPinnedRoot', 'a manifest whose chain ends at a self-signed root the caller pinned nothing for'],
    COLLATERAL_ORIGIN_UNSUPPORTED: ['no', 'origin', 'declarationFor', 'the declaration names a reader, so no unread-origin arm is reached'],
    COLLATERAL_ORIGIN_UNREACHABLE: ['yes', 'fetch', 'fetchFromOrigin', 'a transport that throws on the way to the declared host'],
    COLLATERAL_ORIGIN_REFUSED: ['yes', 'fetch', 'fetchFromOrigin', 'a 403 answered in place of a wrapper'],
    COLLATERAL_BLOB_UNREADABLE: ['yes', 'rim', 'readRimManifest', 'an answer that is not the JSON wrapper the route states'],
    COLLATERAL_SIGNATURE_UNVERIFIED: ['yes', 'rim', 'readRimManifest', 'a wrapper that parses beside a CORIM manifest signed in a shape this path states no rule for weighing'],
    COLLATERAL_IDENTITY_MISMATCH: ['yes', 'rim', 'readRimManifest', 'a wrapper whose own digest does not match the bytes it carries'],
    COLLATERAL_TCB_LEVEL_UNLISTED: ['no', 'origin', 'NVIDIA_RIM', 'the declaration states no identity block, so no level is read'],
    COLLATERAL_STATUS_UNSUPPORTED: ['yes', 'rim', 'readRimManifest', 'a format name outside the three the reference states'],
    COLLATERAL_WINDOW_CLOSED: ['no', 'origin', 'NVIDIA_RIM', 'the declaration states no window members, and last_updated names no validity span'],
    COLLATERAL_NOT_OBSERVED: ['no', 'origin', 'NVIDIA_RIM', 'the declaration states no cache rule, so no kept answer has a record to be unobserved in'],
    COLLATERAL_RETAINED_CHAIN_MISMATCH: ['no', 'origin', 'NVIDIA_RIM', 'no header carries a chain beside retained bytes, so no pair can disagree'],
    COLLATERAL_REVOKED_BY_VENDOR: ['no', 'origin', 'NVIDIA_RIM', 'the route answers a reference document and states no revocation shape'],
  },
};

/**
 * The cells no answer built here can reach, named one by one. An empty list says every cell is either produced
 * by an answer or carried by a declaration fact; a cell that becomes unbuildable is written into the grid and
 * here, because nothing else reports it.
 */
const NOT_EXERCISED: readonly string[] = [];

const FMSPC = '00906EA00000';
const OTHER_FMSPC = '00A0F0000000';
const LEVEL_DATE = '2026-09-01T00:00:00Z';
const NEXT_UPDATE = '2026-10-01T00:00:00Z';
const WITHIN = secondsOf('2026-09-15T00:00:00Z');
const AFTER = secondsOf('2026-11-15T00:00:00Z');
const OBSERVED = secondsOf('2026-09-15T06:00:00Z');
const SERIAL = '5b0bf77b49c75aaba21cf76ad14224c0514fdcf4';
const OTHER_SERIAL = '0badc0de';
const PRODUCT = 'Milan';

const documentVendor = testVendor();
const crlVendor = testVendor({ issuerName: INTEL_PCK_CRL.issuers.processor });
const platformVendor = testVendor({ issuerName: INTEL_PCK_CRL.issuers.platform });

const arkRoot = amdRoot();
const askCert = amdAsk(arkRoot);
const HWID = hwidOf('ashaveri-reachability-chip');
const HWID_HEX = hwidHex(HWID);
const VALID_FROM = writerSeconds('2026-06-01T00:00:00Z');
const VALID_UNTIL = writerSeconds('2033-06-01T00:00:00Z');
const CHIP = amdVcek(askCert, { productName: 'Milan-B0', hwid: HWID, notBefore: VALID_FROM, notAfter: VALID_UNTIL });
const CHAIN = amdChain(askCert.der, arkRoot.der);

const ocspVendor = testVendor();
const OCSP_CERT = ocspDevice(ocspVendor.issuerDer, ocspVendor.signingKey, 0x5b0bf77b);
const OCSP_THIS = secondsOf('2026-09-01T00:00:00Z');
const OCSP_NEXT = secondsOf('2026-10-01T00:00:00Z');
const OCSP_PRODUCED = secondsOf('2026-09-01T06:00:00Z');
const OCSP_REVOKED = secondsOf('2026-08-20T00:00:00Z');

/** The codes the package states it can answer with, in the order the refusal registry carries them. */
const CODES: readonly CollateralErrorCode[] = collateralRefusals().map((entry) => entry.code);

/** The rows of the document's grid, in the order the table carries them. */
interface GridRow {
  readonly origin: string;
  readonly refusal: string;
  readonly reached: string;
  readonly decided: string;
}

function gridRows(): GridRow[] {
  const markdown = readFileSync(new URL('../../../docs/error-codes.md', import.meta.url), 'utf8');
  const lines = markdown.split('\n');
  const at = lines.map((line, index) => (line === HEADER ? index : -1)).filter((index) => index >= 0);
  if (at.length !== 1) {
    throw new Error(`the reachability table header appears ${String(at.length)} times in docs/error-codes.md`);
  }
  const rows: GridRow[] = [];
  for (const line of lines.slice((at[0] as number) + 2)) {
    if (!line.startsWith('| `')) {
      break;
    }
    const cells = line.split('|').map((cell) => cell.trim());
    if (cells.length !== 6) {
      throw new Error(`the row ${line.slice(0, 60)} does not carry exactly four cells`);
    }
    rows.push({
      origin: cells[1] as string,
      refusal: cells[2] as string,
      reached: cells[3] as string,
      decided: cells[4] as string,
    });
  }
  if (rows.length === 0) {
    throw new Error('the reachability table has no rows');
  }
  return rows;
}

/** The grid this file's cells spell, which is what the document has to carry. */
function expectedRows(): GridRow[] {
  const rows: GridRow[] = [];
  for (const origin of SERVED_ORIGINS) {
    for (const code of CODES) {
      const cell = CELLS[origin][code];
      if (cell === undefined) {
        throw new Error(`${origin} carries no cell for ${code}`);
      }
      rows.push({
        origin: `\`${origin}\``,
        refusal: `\`${code}\``,
        reached: cell[0],
        decided: `\`${FILES[cell[1]]}\`, \`${cell[2]}\``,
      });
    }
  }
  return rows;
}

/** Which answer an outcome carries: the code, or the state that carried none. */
function answerOf(answer: { readonly state: string; readonly refusal?: CollateralRefusal }): string {
  return answer.refusal?.code ?? `no refusal, the answer was ${answer.state}`;
}

/**
 * A transport answering with the certificate or body at the first route and the chain at the chain route,
 * and with the header that carries a chain where the declaration names one.
 */
function answering(origin: ReadCollateralOrigin, body: Uint8Array, chain: Uint8Array | null): CollateralTransport {
  const declared = declarationFor(origin);
  const header = 'refusal' in declared ? null : declared.chainHeader;
  return async (input) => {
    if (String(input).endsWith('/cert_chain')) {
      return new Response(chain ?? body);
    }
    return new Response(body, header === null || chain === null ? {} : { headers: { [header]: new TextDecoder().decode(chain) } });
  };
}

function unreachable(): CollateralTransport {
  return async () => {
    throw new Error('the test transport was asked');
  };
}

/** The served pair one JSON document is answered with, under the member its declaration names. */
function servedPair(
  origin: ReadDocumentOrigin,
  input: { readonly status?: string; readonly fmspc?: string; readonly signer?: TestVendor } = {},
): { readonly body: Uint8Array; readonly chain: Uint8Array } {
  const declaration = origin === 'intel-tcb-info' ? INTEL_TCB_INFO : INTEL_QE_IDENTITY;
  const member = declaration.window.documentMember as string;
  const status = input.status ?? 'UpToDate';
  const document = origin === 'intel-tcb-info'
    ? tcbInfo({
      fmspc: input.fmspc ?? FMSPC,
      issueDate: LEVEL_DATE,
      nextUpdate: NEXT_UPDATE,
      levels: [{ tcbDate: LEVEL_DATE, tcbStatus: status }],
    })
    : qeIdentity({
      issueDate: LEVEL_DATE,
      nextUpdate: NEXT_UPDATE,
      levels: [{ isvSvn: 0, tcbDate: LEVEL_DATE, tcbStatus: status }],
    });
  return servedAnswer(document, member, input.signer ?? documentVendor);
}

function intelQuery(origin: ReadDocumentOrigin, over: Partial<CollateralQuery> = {}): CollateralQuery {
  return {
    origin,
    platform: 'sgx',
    cpuType: origin === 'intel-tcb-info' ? FMSPC : null,
    level: { by: 'tcb-date', value: LEVEL_DATE },
    appraisalAt: WITHIN,
    roots: [documentVendor.rootDer],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

type Scenario = () => Promise<string>;

/** Every scenario one JSON document origin can be put through. */
function intelScenarios(origin: ReadDocumentOrigin): Partial<Record<CollateralErrorCode, Scenario>> {
  const declaration = origin === 'intel-tcb-info' ? INTEL_TCB_INFO : INTEL_QE_IDENTITY;
  const pair = servedPair(origin);
  const foreignSigned = servedPair(origin, { signer: { ...documentVendor, signingKey: foreignKey() } });
  const revoked = servedPair(origin, { status: 'OutOfDate' });
  const unknownWord = servedPair(origin, { status: 'LpToDate' });
  const chainOf = servedChainOf([documentVendor.issuerDer, documentVendor.rootDer]);
  const ask = (transport: CollateralTransport, over: Partial<CollateralQuery> = {}): Promise<string> =>
    appraiseCollateral(intelQuery(origin, over), { transport, clock: () => OBSERVED }).then(answerOf);
  return {
    COLLATERAL_INPUT_MISSING: () => ask(unreachable(), { appraisalAt: null }),
    COLLATERAL_ANCHOR_NOT_PINNED: () => ask(answering(origin, pair.body, chainOf), { roots: [Uint8Array.from([1, 2, 3, 4])] }),
    COLLATERAL_ORIGIN_UNREACHABLE: () => ask(unreachable()),
    COLLATERAL_ORIGIN_REFUSED: () => ask(async () => new Response('no', { status: 403 })),
    COLLATERAL_BLOB_UNREADABLE: () => ask(answering(origin, pair.body, null)),
    COLLATERAL_SIGNATURE_UNVERIFIED: () => ask(answering(origin, foreignSigned.body, chainOf)),
    // The identity answer differs from the baseline only where the declaration names the member the document
    // carries it in. Where that slot is null the pair builder ignores the substituted field, so the document
    // would be the baseline bytes and the entry would read as producing a code it can never reach; the case is
    // spelled only for an origin whose declaration carries an identity member.
    ...(declaration.identity.cpuTypeMember === null
      ? {}
      : { COLLATERAL_IDENTITY_MISMATCH: () => ask(answering(origin, servedPair(origin, { fmspc: OTHER_FMSPC }).body, chainOf)) }),
    COLLATERAL_TCB_LEVEL_UNLISTED: () => ask(answering(origin, pair.body, chainOf), {
      level: { by: 'tcb-date', value: '2027-01-01T00:00:00Z' },
    }),
    COLLATERAL_STATUS_UNSUPPORTED: () => ask(answering(origin, unknownWord.body, chainOf)),
    COLLATERAL_WINDOW_CLOSED: () => ask(answering(origin, pair.body, chainOf), { appraisalAt: AFTER }),
    COLLATERAL_NOT_OBSERVED: () => ask(unreachable(), {
      retained: { bytes: pair.body, chain: chainOf, chainSha256: null, observedAt: OBSERVED },
    }),
    COLLATERAL_RETAINED_CHAIN_MISMATCH: () => ask(unreachable(), {
      retained: {
        bytes: pair.body,
        chain: servedChainOf([documentVendor.rootDer, documentVendor.rootDer]),
        chainSha256: sha256(chainOf),
        observedAt: OBSERVED,
      },
    }),
    COLLATERAL_REVOKED_BY_VENDOR: () => ask(answering(origin, revoked.body, chainOf)),
  };
}

function crlQuery(over: Partial<PckCrlQuery> = {}): PckCrlQuery {
  return {
    origin: 'intel-pck-crl',
    platform: 'sgx',
    cpuType: null,
    level: null,
    ca: 'processor',
    certificateSerial: SERIAL,
    appraisalAt: WITHIN,
    roots: [crlVendor.rootDer],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

/** A list of the shape the route serves, with the entries and the signing key a scenario names. */
function listOf(
  input: {
    readonly revoked?: readonly { readonly serial: string; readonly revokedAt: number; readonly reason?: number }[];
    readonly signer?: TestVendor;
    readonly signingKey?: Uint8Array;
    readonly omitNextUpdate?: boolean;
  } = {},
): Uint8Array {
  return writeCrl({
    vendor: input.signer ?? crlVendor,
    thisUpdate: secondsOf('2026-09-01T00:00:00Z'),
    nextUpdate: secondsOf('2026-10-01T00:00:00Z'),
    revoked: input.revoked,
    signingKey: input.signingKey,
    omitNextUpdate: input.omitNextUpdate,
  });
}

function crlScenarios(): Partial<Record<CollateralErrorCode, Scenario>> {
  const crlChain = servedChainOf([crlVendor.issuerDer, crlVendor.rootDer]);
  const plain = listOf();
  const unlisted = listOf({ revoked: [{ serial: OTHER_SERIAL, revokedAt: secondsOf('2026-09-01T00:00:00Z') }] });
  const list = (body: Uint8Array, over: Partial<PckCrlQuery> = {}): Promise<string> =>
    appraisePckCrl(crlQuery(over), { transport: answering('intel-pck-crl', body, crlChain), clock: () => OBSERVED }).then(answerOf);
  return {
    COLLATERAL_INPUT_MISSING: () => list(plain, { certificateSerial: '' }),
    COLLATERAL_ANCHOR_NOT_PINNED: () => list(plain, { roots: [] }),
    COLLATERAL_ORIGIN_UNREACHABLE: () => appraisePckCrl(crlQuery(), { transport: unreachable(), clock: () => OBSERVED }).then(answerOf),
    COLLATERAL_ORIGIN_REFUSED: () => appraisePckCrl(crlQuery(), {
      transport: async () => new Response('no', { status: 403 }),
      clock: () => OBSERVED,
    }).then(answerOf),
    COLLATERAL_BLOB_UNREADABLE: () => list(listOf({ omitNextUpdate: true })),
    COLLATERAL_SIGNATURE_UNVERIFIED: () => list(listOf({ signingKey: foreignKey() })),
    COLLATERAL_IDENTITY_MISMATCH: () => appraisePckCrl(crlQuery({ roots: [platformVendor.rootDer] }), {
      transport: answering('intel-pck-crl', listOf({ signer: platformVendor }), servedChainOf([platformVendor.issuerDer, platformVendor.rootDer])),
      clock: () => OBSERVED,
    }).then(answerOf),
    COLLATERAL_STATUS_UNSUPPORTED: () => list(listOf({
      revoked: [{ serial: SERIAL, revokedAt: secondsOf('2026-09-01T00:00:00Z'), reason: 8 }],
    })),
    COLLATERAL_WINDOW_CLOSED: () => list(unlisted, { appraisalAt: AFTER }),
    COLLATERAL_NOT_OBSERVED: () => appraisePckCrl(crlQuery({
      retained: { bytes: unlisted, chain: crlChain, chainSha256: null, observedAt: OBSERVED },
    }), { transport: unreachable(), clock: () => OBSERVED }).then(answerOf),
    COLLATERAL_RETAINED_CHAIN_MISMATCH: () => appraisePckCrl(crlQuery({
      retained: {
        bytes: plain,
        chain: servedChainOf([crlVendor.rootDer, crlVendor.rootDer]),
        chainSha256: sha256(crlChain),
        observedAt: OBSERVED,
      },
    }), { transport: unreachable(), clock: () => OBSERVED }).then(answerOf),
    COLLATERAL_REVOKED_BY_VENDOR: () => list(listOf({
      revoked: [{ serial: SERIAL, revokedAt: secondsOf('2026-09-01T00:00:00Z'), reason: 1 }],
    })),
  };
}

function chainScenarios(): Partial<Record<CollateralErrorCode, Scenario>> {
  const askChain = (transport: CollateralTransport, over: Partial<VcekChainQuery> = {}): Promise<string> =>
    appraiseVcekChain(chainQuery(over), { transport, clock: () => OBSERVED }).then(answerOf);
  const pair = answering('amd-kds', CHIP.der, CHAIN);
  return {
    COLLATERAL_INPUT_MISSING: () => askChain(unreachable(), { appraisalAt: null }),
    COLLATERAL_ANCHOR_NOT_PINNED: () => askChain(unreachable(), { roots: [] }),
    COLLATERAL_ORIGIN_UNREACHABLE: () => askChain(unreachable()),
    COLLATERAL_ORIGIN_REFUSED: () => askChain(async (input) => (String(input).endsWith('/cert_chain')
      ? new Response('gone', { status: 404 })
      : new Response(CHIP.der))),
    COLLATERAL_BLOB_UNREADABLE: () => askChain(answering('amd-kds', CHIP.der, new TextEncoder().encode('no certificate here'))),
    COLLATERAL_SIGNATURE_UNVERIFIED: () => askChain(pair, { appraisalAt: writerSeconds('2024-01-01T00:00:00Z') }),
    COLLATERAL_IDENTITY_MISMATCH: () => askChain(answering(
      'amd-kds',
      amdVcek(askCert, {
        productName: 'Milan-B0',
        hwid: hwidOf('ashaveri-another-chip'),
        notBefore: VALID_FROM,
        notAfter: VALID_UNTIL,
      }).der,
      CHAIN,
    )),
    COLLATERAL_NOT_OBSERVED: () => askChain(unreachable(), {
      retained: { bytes: CHIP.der, chain: CHAIN, chainSha256: null, observedAt: OBSERVED },
    }),
    COLLATERAL_RETAINED_CHAIN_MISMATCH: () => askChain(unreachable(), {
      retained: {
        bytes: CHIP.der,
        chain: amdChain(arkRoot.der, arkRoot.der),
        chainSha256: sha256(CHAIN),
        observedAt: OBSERVED,
      },
    }),
  };
}

/** One answer under the vendor this file pins, in the shape the route serves it. */
function ocspAnswer(over: Partial<OcspInput> = {}): Uint8Array {
  return writeOcspResponse({
    responder: ocspVendor,
    certificate: OCSP_CERT.der,
    issuer: ocspVendor.issuerDer,
    producedAt: OCSP_PRODUCED,
    thisUpdate: OCSP_THIS,
    nextUpdate: OCSP_NEXT,
    ...over,
  });
}

function ocspQuery(over: Partial<OcspQuery> = {}): OcspQuery {
  return {
    origin: 'ocsp',
    platform: 'sgx',
    cpuType: null,
    level: null,
    ocspCertificate: OCSP_CERT.der,
    ocspIssuer: ocspVendor.issuerDer,
    appraisalAt: WITHIN,
    roots: [ocspVendor.rootDer],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

function ocspScenarios(): Partial<Record<CollateralErrorCode, Scenario>> {
  const ask = (transport: CollateralTransport, over: Partial<OcspQuery> = {}): Promise<string> =>
    appraiseOcspResponse(ocspQuery(over), { transport, clock: () => OBSERVED }).then(answerOf);
  const served = (body: Uint8Array): CollateralTransport => async () => new Response(body);
  return {
    COLLATERAL_INPUT_MISSING: () => ask(unreachable(), { appraisalAt: null }),
    COLLATERAL_ANCHOR_NOT_PINNED: () => ask(served(ocspAnswer()), { roots: [Uint8Array.from([1, 2, 3, 4])] }),
    COLLATERAL_ORIGIN_UNREACHABLE: () => ask(unreachable()),
    COLLATERAL_ORIGIN_REFUSED: () => ask(served(ocspAnswer({ responseStatus: 3 }))),
    COLLATERAL_BLOB_UNREADABLE: () => ask(served(ocspAnswer({ nextUpdate: null }))),
    COLLATERAL_SIGNATURE_UNVERIFIED: () => ask(served(ocspAnswer({ signingKey: foreignKey() }))),
    COLLATERAL_IDENTITY_MISMATCH: () => ask(served(ocspAnswer({ serialHex: OTHER_SERIAL }))),
    COLLATERAL_STATUS_UNSUPPORTED: () => ask(served(ocspAnswer({ status: 'unknown' }))),
    COLLATERAL_WINDOW_CLOSED: () => ask(served(ocspAnswer()), { appraisalAt: AFTER }),
    COLLATERAL_NOT_OBSERVED: () => ask(unreachable(), {
      retained: { bytes: ocspAnswer(), chain: null, chainSha256: null, observedAt: OBSERVED },
    }),
    COLLATERAL_RETAINED_CHAIN_MISMATCH: () => ask(unreachable(), {
      retained: {
        bytes: ocspAnswer(),
        chain: servedChainOf([ocspVendor.rootDer, ocspVendor.rootDer]),
        chainSha256: sha256(ocspVendor.issuerDer),
        observedAt: OBSERVED,
      },
    }),
    COLLATERAL_REVOKED_BY_VENDOR: () => ask(served(ocspAnswer({ status: 'revoked', revokedAt: OCSP_REVOKED }))),
  };
}

const RIM_ID = 'gpu-rim-0001';

function rimQuery(over: Partial<CollateralQuery> = {}): CollateralQuery {
  return {
    origin: 'nvidia-rim',
    platform: 'sgx',
    cpuType: null,
    level: null,
    rimId: RIM_ID,
    appraisalAt: WITHIN,
    roots: [documentVendor.rootDer],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

/** The address the route publishes for the id the question names. */
function rimAddress(): string {
  const asked = requestUrl(rimQuery(), NVIDIA_RIM);
  if (typeof asked !== 'string') throw new Error(`the RIM address was refused: ${asked.refusal.detail}`);
  return asked;
}

/** The identifiers the fixture's `ds:SignedInfo` is written in, which are the ones the profile reads. */
const RIM_DS = 'http://www.w3.org/2000/09/xmldsig#';
const RIM_C14N11 = 'http://www.w3.org/2006/12/xml-c14n11';
const RIM_ECDSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
const RIM_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
const RIM_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

/**
 * The canonical form of the fixture manifest with its `ds:Signature` element left out, spelled from the
 * canonicalization rules the way `test/rim.test.ts` pins them: the declarations an element has in scope by prefix
 * with the default first, the document element's attributes by name, the comment dropped, `<Meta/>` as a start tag
 * and an end tag, the closing bracket of an attribute value as the character it names, and the carriage return of
 * the measured text as `&#xD;`. The attribute values are the ones `test/rim-document-writer.ts` writes by default.
 * This row needs a document whose digest holds because the chain walk sits behind the digest, and a copy that
 * drifted would answer with the digest refusal rather than the one the row names, which is where the two copies
 * are kept in step.
 */
const RIM_CANONICAL_DOCUMENT = '<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd"'
  + ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#" corpus="false" name="GH100 > driver"'
  + ' tagId="NV_GPU_DRIVER_GH100_550.127.08" version="550.127.08"><Meta></Meta><Payload>'
  + '<Measurements>sha384 &gt; a&#xD;b</Measurements></Payload></SoftwareIdentity>';

/** The `ds:SignedInfo` the profile reads, carrying the digest of the canonical document above. */
function rimSignedInfo(digest: string): string {
  return '<ds:SignedInfo>'
    + `<ds:CanonicalizationMethod Algorithm="${RIM_C14N11}"/>`
    + `<ds:SignatureMethod Algorithm="${RIM_ECDSA_SHA384}"/>`
    + '<ds:Reference URI="">'
    + `<ds:Transforms xmlns:ds="${RIM_DS}">`
    + `<ds:Transform Algorithm="${RIM_ENVELOPED}"/>`
    + `<ds:Transform Algorithm="${RIM_C14N11}"/>`
    + '</ds:Transforms>'
    + `<ds:DigestMethod Algorithm="${RIM_SHA384}"/>`
    + `<ds:DigestValue>${digest}</ds:DigestValue>`
    + '</ds:Reference></ds:SignedInfo>';
}

/**
 * One `TCG` manifest in the wrapper the route answers it in, read far enough to reach the chain walk: the digest
 * it carries is the one the canonicalized document holds, so the answer is whatever the certificates and the
 * pinned roots decide, and the chain is handed in because which link the walk stops at is the cell's own fact.
 */
function rimWeighedWrapper(chain: ReturnType<typeof rimChain> = rimChain()): Uint8Array {
  const digest = wrap(Buffer.from(sha384(utf8(RIM_CANONICAL_DOCUMENT))).toString('base64'));
  const signedInfo = rimSignedInfo(digest);
  const document = rimManifest({ chain, signedInfo, signedInfoBytes: utf8(signedInfo) });
  return writeRimWrapper({ id: RIM_ID, rim: manifestBytes(document) });
}

/**
 * The refusal code an answer carries.
 *
 * Every RIM cell of the grid is made of a refusal, so an answer that weighed its manifest instead of refusing one
 * is an answer no cell of that row names, and that is said here rather than read off a missing field.
 */
function rimRefusalCode(outcome: RimReadOutcome): CollateralErrorCode {
  if (!('refusal' in outcome)) {
    throw new Error('the RIM reader weighed the answer and handed back no refusal for a grid cell to name');
  }
  return outcome.refusal.code;
}

/**
 * The RIM cells, produced through the three public entry points a RIM reading is made of.
 *
 * No appraisal path answers for this origin, because no verdict does, so each cell is read off the outcome
 * `readRimManifest` hands back, off the address `requestUrl` refuses to spell, or off the status
 * `fetchFromOrigin` met: a `CORIM` answer carries its refusal beside the wrapper it read, and the walk answers
 * the question a caller pinned nothing for.
 */
function rimScenarios(): Partial<Record<CollateralErrorCode, Scenario>> {
  const wrapper = (body: Uint8Array, over: Partial<CollateralQuery> = {}): Promise<string> =>
    Promise.resolve(rimRefusalCode(readRimManifest(body, rimQuery(over), NVIDIA_RIM)));
  const asked = async (transport: CollateralTransport): Promise<string> => {
    const out = await fetchFromOrigin(rimAddress(), NVIDIA_RIM, { transport });
    return 'refusal' in out ? out.refusal.code : 'an answer was fetched and carried no refusal';
  };
  return {
    COLLATERAL_INPUT_MISSING: async () => {
      const addressed = requestUrl(rimQuery({ rimId: null }), NVIDIA_RIM);
      return typeof addressed === 'string' ? `an address was spelled with no id: ${addressed}` : addressed.refusal.code;
    },
    COLLATERAL_ORIGIN_UNREACHABLE: () => asked(unreachable()),
    COLLATERAL_ORIGIN_REFUSED: () => asked(async () => new Response('{}', { status: 403 })),
    COLLATERAL_ANCHOR_NOT_PINNED: () => wrapper(rimWeighedWrapper()),
    COLLATERAL_BLOB_UNREADABLE: () => wrapper(new TextEncoder().encode('not a wrapper')),
    COLLATERAL_SIGNATURE_UNVERIFIED: () => wrapper(writeRimWrapper({ id: RIM_ID, format: 'CORIM' })),
    COLLATERAL_IDENTITY_MISMATCH: () => wrapper(writeRimWrapper({ id: RIM_ID, digest: '0'.repeat(64) })),
    COLLATERAL_STATUS_UNSUPPORTED: () => wrapper(writeRimWrapper({ id: RIM_ID, format: 'NOT-A-FORMAT' })),
  };
}

function chainQuery(over: Partial<VcekChainQuery> = {}): VcekChainQuery {
  return {
    origin: 'amd-kds',
    platform: 'sgx',
    cpuType: null,
    level: null,
    product: PRODUCT,
    hwid: HWID_HEX,
    appraisalAt: WITHIN,
    roots: [arkRoot.der],
    retained: null,
    onAbsent: 'unassessed',
    ...over,
  };
}

/** The fact a `no` cell rests on, read out of a declaration rather than out of the code that acts on it. */
type DeclarationFact = (origin: ReadCollateralOrigin) => boolean;

/** Whether the origin is served and its declaration states a reader, which is what no unread origin can state. */
function originHasAReader(origin: ReadCollateralOrigin): boolean {
  const declared = declarationFor(origin);
  return !('refusal' in declared) && SERVED_ORIGINS.includes(origin) && declared.reader.as !== 'declared-only';
}

/**
 * The declaration facts behind the `no` cells, keyed first by the code a cell cites and then by the origin that
 * may cite it. The code picks the fact because a refusal is one question about the package's own vocabulary, and
 * the origin narrows it because which member that question is asked of belongs to the origin. A pair missing here
 * is a `no` no declaration is written for, so the run names the pair instead of letting the fact beside it, meant
 * for another origin or another code, certify the cell.
 */
const NO_CELL_FACTS: Readonly<Partial<Record<CollateralErrorCode, Readonly<Partial<Record<ReadCollateralOrigin, DeclarationFact>>>>>> = {
  COLLATERAL_ORIGIN_UNSUPPORTED: {
    'intel-tcb-info': originHasAReader,
    'intel-qe-identity': originHasAReader,
    'intel-pck-crl': originHasAReader,
    'amd-kds': originHasAReader,
    ocsp: originHasAReader,
    'nvidia-rim': originHasAReader,
  },
  COLLATERAL_IDENTITY_MISMATCH: {
    'intel-qe-identity': () => INTEL_QE_IDENTITY.identity.cpuTypeMember === null,
  },
  COLLATERAL_TCB_LEVEL_UNLISTED: {
    'intel-pck-crl': () => !Object.hasOwn(INTEL_PCK_CRL, 'identity') && INTEL_PCK_CRL.serialMember === 'certificateSerial',
    'amd-kds': () => !Object.hasOwn(AMD_KDS, 'identity'),
    ocsp: () => !Object.hasOwn(NVIDIA_OCSP, 'identity') && NVIDIA_OCSP.cache.keyMembers.includes('ocspCertificate'),
    'nvidia-rim': () => !Object.hasOwn(NVIDIA_RIM, 'identity') && NVIDIA_RIM.reader.as === 'rim-wrapper',
  },
  COLLATERAL_STATUS_UNSUPPORTED: {
    'amd-kds': () => !Object.hasOwn(AMD_KDS, 'status'),
  },
  COLLATERAL_WINDOW_CLOSED: {
    'amd-kds': () => !Object.hasOwn(AMD_KDS, 'window'),
    // The declaration states no member a window is read from, and `last_updated` is the vendor's text for when
    // a file was updated, which bounds nothing and so can no more close than it can open.
    'nvidia-rim': () => !Object.hasOwn(NVIDIA_RIM, 'window') && NVIDIA_RIM.reader.as === 'rim-wrapper',
  },
  COLLATERAL_NOT_OBSERVED: {
    // A kept answer is refused as unobserved where the declaration names the record it belongs to; this one
    // names none, because no verdict of this origin's would have a key to be kept under.
    'nvidia-rim': () => NVIDIA_RIM.cache === null,
  },
  COLLATERAL_RETAINED_CHAIN_MISMATCH: {
    'nvidia-rim': () => NVIDIA_RIM.chainHeader === null && NVIDIA_RIM.cache === null,
  },
  COLLATERAL_REVOKED_BY_VENDOR: {
    'amd-kds': () => !Object.hasOwn(AMD_KDS, 'status')
      && AMD_KDS.routes.every((route) => route.answer !== 'der-crl' && route.answer !== 'der-ocsp-response'),
    'nvidia-rim': () => NVIDIA_RIM.routes.every((route) => route.answer !== 'der-crl' && route.answer !== 'der-ocsp-response'),
  },
};

/** Whether a `no` cell is carried by the fact written for exactly that origin and that code. */
function noCellHolds(origin: ReadCollateralOrigin, code: CollateralErrorCode): boolean {
  const fact = NO_CELL_FACTS[code]?.[origin];
  if (fact === undefined) {
    throw new Error(`the no cell ${origin} / ${code} cites no declaration fact`);
  }
  return fact(origin);
}

/** Whether the cited file declares the symbol, rather than merely mentioning it in a sentence. */
function declaredIn(file: string, symbol: string): boolean {
  const source = readFileSync(new URL(`../../../${file}`, import.meta.url), 'utf8');
  return new RegExp(`^(?:export )?(?:async )?(?:function|const) ${symbol}\\b`, 'mu').test(source);
}

function cellsOf(reached: Reached): string[] {
  const found: string[] = [];
  for (const origin of SERVED_ORIGINS) {
    for (const code of CODES) {
      const cell = CELLS[origin][code];
      if (cell !== undefined && cell[0] === reached) {
        found.push(`${origin} ${code}`);
      }
    }
  }
  return found;
}

describe('the reachability grid docs/error-codes.md carries', () => {
  it('is the read origins crossed with the declared codes, in those orders', () => {
    expect(CODES).toHaveLength(14);
    expect(SERVED_ORIGINS).toHaveLength(6);
    const rows = gridRows();
    expect(rows).toEqual(expectedRows());
    expect(rows).toHaveLength(SERVED_ORIGINS.length * CODES.length);
    for (const origin of SERVED_ORIGINS) {
      expect(rows.filter((row) => row.origin === `\`${origin}\``), origin).toHaveLength(CODES.length);
    }
    for (const unread of Object.keys(ORIGIN_DECLARATIONS).filter((name) => !SERVED_ORIGINS.includes(name as ReadCollateralOrigin))) {
      expect(rows.some((row) => row.origin.includes(unread)), `${unread} holds a row`).toBe(false);
    }
  });

  it('names a symbol declared in the file each cell cites', () => {
    for (const [origin, code, file, symbol] of citedSymbols()) {
      expect(declaredIn(file, symbol), `${origin} ${code} cites ${symbol} in ${file}`).toBe(true);
    }
  });

  it('produces every yes cell by handing a public entry point an answer', async () => {
    const producers: Record<ReadCollateralOrigin, Partial<Record<CollateralErrorCode, Scenario>>> = {
      'intel-tcb-info': intelScenarios('intel-tcb-info'),
      'intel-qe-identity': intelScenarios('intel-qe-identity'),
      'intel-pck-crl': crlScenarios(),
      'amd-kds': chainScenarios(),
      ocsp: ocspScenarios(),
      'nvidia-rim': rimScenarios(),
    };
    for (const origin of SERVED_ORIGINS) {
      for (const code of CODES) {
        const cell = CELLS[origin][code] as CellSpec;
        if (cell[0] !== 'yes') {
          continue;
        }
        const produce = producers[origin][code];
        expect(produce, `${origin} ${code} has no scenario for ${cell[3]}`).toBeDefined();
        const reached = await (produce as Scenario)();
        expect(reached, `${origin} ${code}: ${cell[3]}`).toBe(code);
      }
    }
  });

  it('carries every no cell on a fact its declaration states', () => {
    for (const cell of cellsOf('no')) {
      const [origin, code] = cell.split(' ') as [ReadCollateralOrigin, CollateralErrorCode];
      expect(noCellHolds(origin, code), `${cell}: ${CELLS[origin][code]?.[3]}`).toBe(true);
    }
  });

  it('leaves as many cells unexercised as it names', () => {
    expect(cellsOf('not exercised').sort()).toEqual([...NOT_EXERCISED].sort());
  });

  /**
   * The RIM row holds because an arm weighs its wrapper and weighs the `TCG` manifest inside it, and the cells
   * that read `no` hold because the same declaration states no window, no identity block, no chain header, no
   * cache rule and no revocation shape. That is the grid's way of stating that no RIM reading reaches a verdict.
   * What the reader answers says the same thing from its side, so this case reads both and refuses a grid that
   * quietly grants this origin a row it cannot fill: a `CORIM` wrapper answers with the read and the refusal
   * beside it, a `TCG` wrapper whose manifest holds nothing this path can weigh answers with a refusal alone, and
   * a chain that ends at a self-signed name the question pinned nothing for answers with the anchor refusal its
   * row names.
   */
  it('holds the RIM to the reach its declaration and its reader both state', () => {
    const declared = ORIGIN_DECLARATIONS['nvidia-rim'];
    if (declared.reader.as !== 'rim-wrapper') throw new Error('the RIM was granted a verdict its reader does not reach');
    expect(declared.reader.reads).toContain('readRimManifest');
    expect(declared.reader.reads).toContain('sha256');
    expect(declared.reader.reads).toContain('the digest of the canonicalized document');
    expect(declared.reader.reads).toContain('the signature over the canonicalized signed element');
    expect(declared.reader.reads).toContain('walked to a root the caller pins');
    expect(declared.reader.lacks).toContain('compares a device measurement');
    const cells = CELLS['nvidia-rim'];
    for (const code of [
      'COLLATERAL_ORIGIN_UNSUPPORTED',
      'COLLATERAL_TCB_LEVEL_UNLISTED',
      'COLLATERAL_WINDOW_CLOSED',
      'COLLATERAL_NOT_OBSERVED',
      'COLLATERAL_RETAINED_CHAIN_MISMATCH',
      'COLLATERAL_REVOKED_BY_VENDOR',
    ] as const) {
      expect(cells[code][0], code).toBe('no');
    }
    expect(cells.COLLATERAL_ANCHOR_NOT_PINNED[0], 'the walk answers a chain that reaches no root the caller pinned').toBe('yes');
    expect(requestUrl(rimQuery(), NVIDIA_RIM), 'the route is published even where no verdict reads its answer').toBe(
      'https://rim.attestation.nvidia.com/v1/rim/gpu-rim-0001',
    );

    const paired = readRimManifest(writeRimWrapper({ id: RIM_ID, format: 'CORIM' }), rimQuery(), NVIDIA_RIM);
    if (!('read' in paired) || !('refusal' in paired)) {
      throw new Error('the wrapper did not answer with the read and the refusal this cell pairs');
    }
    expect(paired.read.format).toBe('CORIM');
    expect(paired.read.id).toBe(RIM_ID);
    expect(paired.read.blobs).toHaveLength(1);
    expect(paired.read.tagId).toBeNull();
    expect(paired.read.anchorDigest).toBeNull();
    expect(paired.refusal.code).toBe('COLLATERAL_SIGNATURE_UNVERIFIED');
    expect(paired.refusal.detail).toContain('CORIM');
    expect(paired.refusal.detail).toContain('no rule');

    const refused = readRimManifest(writeRimWrapper({ id: RIM_ID }), rimQuery(), NVIDIA_RIM);
    if ('read' in refused) throw new Error('a TCG wrapper carrying an opaque manifest answered with a reading and no refusal');
    expect(refused.refusal.code).toBe('COLLATERAL_BLOB_UNREADABLE');

    // The row names the arm as well as the code, so the answer the scenario hands is read here for the sentence
    // it carries: a chain the walk believed link by link, ending at a self-signed name this question pinned
    // nothing for, which is the anchor refusal rather than the unverified signature one.
    const unpinned = readRimManifest(rimWeighedWrapper(), rimQuery(), NVIDIA_RIM);
    if (!('refusal' in unpinned)) throw new Error('the chain walk answered with a reading and no refusal');
    expect(unpinned.refusal.code).toBe('COLLATERAL_ANCHOR_NOT_PINNED');
    expect(unpinned.refusal.detail).toContain('pinned nothing for');
  });
});

/** Each cited file and symbol, one entry per cell of the grid. */
function citedSymbols(): readonly (readonly [string, string, string, string])[] {
  const out: [string, string, string, string][] = [];
  for (const origin of SERVED_ORIGINS) {
    for (const code of CODES) {
      const cell = CELLS[origin][code] as CellSpec;
      out.push([origin, code, FILES[cell[1]], cell[2]]);
    }
  }
  return out;
}
