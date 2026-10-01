import { describe, expect, it } from 'vitest';
import {
  MARKING_MEMBER_NAME,
  PROVENANCE_V1_MEMBER_SCHEME,
  emptyRegion,
  hashRequest,
  issueReceipt,
  provenanceV1Member,
  signingKeyFromSeed,
  type Marking,
  type ReceiptPayload,
  type SigningKey,
  type VerifiedReceipt,
} from '@ashaveri/receipt';
import { AshaveriClient, verifyCompletionReceipt, wrapOpenAI, type ChatCompletionChunk } from '../src/index.js';
import {
  createFakeGateway,
  FAKE_BASE_URL,
  FAKE_IAT,
  FAKE_RECEIPT_ID,
  type FakeGatewayOptions,
} from './mock-gateway.js';

/**
 * The marking claim checked by the client that is holding the response, rather than by someone who
 * kept the bytes and thought to look.
 *
 * Most of what is below goes through a live verification: the fake gateway writes a marked response
 * and the receipt that attests it, and the client reads both and decides. Three things get pinned
 * together. The region the client checks is the one the published rule names, so the client's verdict
 * and a third party's detector verdict are about the same bytes. The failure a marking produces is
 * `MARK_MISMATCH`, and `INVALID_SIGNATURE` stays the code for a receipt that is not authentic: a
 * reader told "the mark does not match" needs to know the document itself verified. And the bytes the
 * mark is read out of have to be the bytes the receipt attests, which is checked rather than assumed,
 * because a region lifted out of a document nobody signed is a verdict about the wrong response.
 *
 * The claim belongs to the member, not to a number: every receipt this format writes names `mk` and
 * attests one region, so the step is taken because the member is there and every case below is
 * answered by that. A deployment that was never asked to mark names the empty region rather than
 * saying nothing about a mark, which is the other half of what the cases hold.
 */

const MESSAGES = [{ role: 'user' as const, content: 'hi' }];
const MODEL = 'fake-model';
const KEY = signingKeyFromSeed(new Uint8Array(32).fill(21));
const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);

function clientFor(options: FakeGatewayOptions): AshaveriClient {
  const gateway = createFakeGateway(options);
  return new AshaveriClient({ baseUrl: FAKE_BASE_URL, fetch: gateway.fetch, verify: 'receipt' });
}

/** The identity of a refusal, so a case cannot be satisfied by just any error. */
async function failureFrom(run: () => Promise<unknown>): Promise<{ name: string; code: string; message: string }> {
  try {
    await run();
  } catch (err) {
    const error = err as { name?: string; code?: string; message?: string };
    return { name: error.name ?? 'none', code: error.code ?? 'none', message: error.message ?? '' };
  }
  throw new Error('expected a refusal and the call returned normally');
}

/** Drains a streamed completion and reports the refusal it ended with. */
async function streamedFailure(options: FakeGatewayOptions) {
  const client = clientFor(options);
  const stream = await client.chat.completions.stream({ model: MODEL, messages: MESSAGES });
  return failureFrom(async () => {
    for await (const chunk of stream) {
      expect(chunk).toBeDefined();
    }
    await stream.receipt;
  });
}

/** The member's text, spelled the way the published rule spells it. */
function memberText(at: number): string {
  return `${JSON.stringify(MARKING_MEMBER_NAME)}:${JSON.stringify(provenanceV1Member(at))}`;
}

/** A buffered body carrying the member once, with whitespace of the upstream's own before it. */
function markedBody(...members: string[]): string {
  return `{"id":"chatcmpl-handbuilt","object":"chat.completion","choices":[],"usage":null${members
    .map((member) => `,\n  ${member}`)
    .join('')}}`;
}

/** The twelve fields every receipt carries, over `responseBytes`, named apart from the five it states about itself. */
function fieldsOver(responseBytes: Uint8Array): Omit<ReceiptPayload, 'v' | 'mk' | 'sd' | 'cva' | 'itm'> {
  return {
    iss: 'handbuilt-issuer',
    ins: 'handbuilt-instance',
    iat: FAKE_IAT,
    nce: new Uint8Array(16).fill(3),
    req: hashRequest(utf8('the request')),
    res: hashRequest(responseBytes),
    mdl: MODEL,
    wts: new Uint8Array(32).fill(8),
    meas: { tee: 'software', m: new Uint8Array(32).fill(6) },
    att: { d: new Uint8Array(32).fill(9), ts: FAKE_IAT, url: `${FAKE_BASE_URL}/attestation` },
    epk: 0,
    tok: { p: 1, c: 1 },
  };
}

/**
 * The one receipt this format writes over `responseBytes`: the twelve shared fields, the marking the case
 * names, and the four members a receipt states about itself. The disclosure, the anchor and the item list
 * are filled the way an issuing gateway fills them, because the claim under test is `mk`'s and the rest of
 * the document has to be a document a reader of this build can open.
 */
function receiptOver(responseBytes: Uint8Array, mk: Marking, by: SigningKey = KEY): Uint8Array {
  const fields = fieldsOver(responseBytes);
  const payload: ReceiptPayload = {
    ...fields,
    v: 1,
    mk,
    sd: { name: 'host clock', uncertaintySeconds: null },
    cva: {
      collateral: { presence: 'held', sha256: hashRequest(utf8('the collateral the appraisal ran on')) },
      validity: { presence: 'not-taken-in', reason: 'the collector read no window' },
    },
    itm: [{ t: fields.iat, d: hashRequest(utf8('the first item of the response')) }],
  };
  return issueReceipt(payload, by);
}

/**
 * One live verification on hand-built bytes. `responseHash` defaults to the digest of the bytes,
 * which is what a client that read them straight would hand over; a case that means to lie about one
 * of the two names the other itself. The receipt that comes back is returned rather than discarded,
 * because the cases that expect a refusal and the cases that expect to get through are answered by
 * the same call and only the second one has an outcome to state.
 */
function checkLive(receiptBytes: Uint8Array, responseBytes: Uint8Array, verifyKey: Uint8Array, responseHash?: Uint8Array): VerifiedReceipt {
  return verifyCompletionReceipt({
    receiptBytes,
    nonce: new Uint8Array(16).fill(3),
    requestHash: hashRequest(utf8('the request')),
    responseHash: responseHash ?? hashRequest(responseBytes),
    responseBytes,
    verifyKey,
    nowMillis: FAKE_IAT * 1000,
  });
}

describe('a live client checking the mark it was sent', () => {
  it('accepts a marked buffered completion, member and all', async () => {
    const result = await clientFor({ marking: 'provenance-v1' }).chat.completions.create({
      model: MODEL,
      messages: MESSAGES,
    });
    expect(result.receipt?.payload.v).toBe(1);
    const member = (result.completion as unknown as Record<string, unknown>)[MARKING_MEMBER_NAME];
    expect(JSON.stringify(member)).toContain(PROVENANCE_V1_MEMBER_SCHEME);
  });

  it('accepts a marked stream, holding the frame across whatever slices it arrived in', async () => {
    const stream = await clientFor({ marking: 'provenance-v1', streamChunkBytes: 7 }).chat.completions.stream({
      model: MODEL,
      messages: MESSAGES,
    });
    const chunks: ChatCompletionChunk[] = [];
    for await (const chunk of stream) {
      chunks.push(chunk);
    }
    expect((await stream.receipt)?.payload.v).toBe(1);
    // The mark rode inside a well-formed chunk, so the consumer of the stream saw it as one, and it
    // is the last chunk: the frame goes ahead of the sentinel, not after the stream has closed.
    expect(chunks[chunks.length - 1]).toMatchObject({ choices: [] });
    expect(
      (chunks[chunks.length - 1] as unknown as Record<string, unknown>)[MARKING_MEMBER_NAME],
    ).toBeDefined();
    expect(chunks.filter((chunk) => chunk.choices.length === 0)).toHaveLength(1);
  });

  it('accepts an unmarked completion whose receipt declares the absence', async () => {
    const buffered = await clientFor({ marking: 'none' }).chat.completions.create({
      model: MODEL,
      messages: MESSAGES,
    });
    expect(buffered.receipt?.payload).toMatchObject({ v: 1, mk: { sch: 'none' } });
    expect((buffered.completion as unknown as Record<string, unknown>)[MARKING_MEMBER_NAME]).toBeUndefined();

    const stream = await clientFor({ marking: 'none' }).chat.completions.stream({ model: MODEL, messages: MESSAGES });
    for await (const chunk of stream) {
      expect((chunk as unknown as Record<string, unknown>)[MARKING_MEMBER_NAME]).toBeUndefined();
    }
    expect((await stream.receipt)?.payload.v).toBe(1);
  });

  it('accepts a completion from a deployment that was never asked to mark, and reads its declared absence', async () => {
    // No marking option at all is the same document as the one that declares none: the member is
    // required, so this receipt states the empty region rather than leaving the question open.
    const result = await clientFor({}).chat.completions.create({ model: MODEL, messages: MESSAGES });
    expect(result.receipt?.payload.v).toBe(1);
    expect(result.receipt?.payload.mk).toEqual({ sch: 'none', d: hashRequest(emptyRegion()) });
  });

  it('checks the mark on the wrapper path too, where the bytes arrive through a tee', async () => {
    const gateway = createFakeGateway({ marking: 'provenance-v1' });
    const wrapped = wrapOpenAI({ apiKey: 'test-key', fetch: gateway.fetch });
    const response = await wrapped.fetch(`${FAKE_BASE_URL}/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: MODEL, messages: MESSAGES, stream: true }),
    });
    expect(await response.text()).toContain('"choices":[]');
    expect((await wrapped.ashaveri.getReceipt(FAKE_RECEIPT_ID)).payload.v).toBe(1);
  });
});

describe('what a live client refuses', () => {
  it('refuses a marked response whose digest does not cover its region', async () => {
    const misattested = (payload: ReceiptPayload): ReceiptPayload => ({
      ...payload,
      mk: { ...payload.mk, d: hashRequest(utf8(memberText(FAKE_IAT + 1))) },
    });
    const failure = await failureFrom(() =>
      clientFor({ marking: 'provenance-v1', mutatePayload: misattested }).chat.completions.create({
        model: MODEL,
        messages: MESSAGES,
      }),
    );
    expect(failure.name).toBe('ReceiptError');
    expect(failure.code).toBe('MARK_MISMATCH');
    expect(failure.message).toContain('mk.d');
  });

  it('refuses the same on a stream, where a whole frame is the region', async () => {
    const misattested = (payload: ReceiptPayload): ReceiptPayload => ({
      ...payload,
      mk: { ...payload.mk, d: new Uint8Array(32).fill(4) },
    });
    const failure = await streamedFailure({ marking: 'provenance-v1', mutatePayload: misattested });
    expect(failure.name).toBe('ReceiptError');
    expect(failure.code).toBe('MARK_MISMATCH');
  });

  it('refuses a stripped mark as the bytes moving, which is not a marking failure', async () => {
    const strip = (body: string): string => {
      const at = body.indexOf(`,${memberText(FAKE_IAT)}`);
      if (at >= 0) {
        return `${body.slice(0, at)}}`;
      }
      return body.replace(/data: [^\n]*"choices":\[\][^\n]*\n\n/, '');
    };
    const failure = await failureFrom(() =>
      clientFor({ marking: 'provenance-v1', mutateResponseBody: strip }).chat.completions.create({
        model: MODEL,
        messages: MESSAGES,
      }),
    );
    // Deleting the member takes the whole response's digest with it, which is the first acceptance the
    // format states: no reader keeps a verifying receipt over a response they cleaned.
    expect(failure.name).toBe('SdkError');
    expect(failure.code).toBe('RESPONSE_HASH_MISMATCH');
  });

  it('refuses a streamed response whose marking frame was removed', async () => {
    const failure = await streamedFailure({
      marking: 'provenance-v1',
      mutateResponseBody: (body) => body.replace(/data: [^\n]*"choices":\[\][^\n]*\n\n/, ''),
    });
    expect(failure.code).toBe('RESPONSE_HASH_MISMATCH');
  });

  it('accepts a mark the sender wrote behind its own sentinel, because this client reads to the end', async () => {
    // The frame belongs ahead of the sentinel, and the gateway writes it there; the shape where it
    // lands last is a stream that had something to say after its own sentinel. Either way the bytes a
    // client that drains the stream holds are the bytes the receipt attests, so the mark is checkable
    // and the position changes nothing about that verdict.
    const stream = await clientFor({ marking: 'provenance-v1', markAfterSentinel: true }).chat.completions.stream({
      model: MODEL,
      messages: MESSAGES,
    });
    const chunks: ChatCompletionChunk[] = [];
    for await (const chunk of stream) {
      chunks.push(chunk);
    }
    expect((await stream.receipt)?.payload.v).toBe(1);
    expect(chunks[chunks.length - 1]).toMatchObject({ choices: [] });
  });

  it('keeps "not authentic" apart from "the marking does not match" over the same bytes', async () => {
    const responseBytes = utf8(markedBody(memberText(FAKE_IAT)));
    const mk: Marking = { sch: 'provenance-v1', d: new Uint8Array(32).fill(4) };
    const receiptBytes = receiptOver(responseBytes, mk);
    // A signature that no longer travels, over a payload whose marking is just as wrong as it was:
    // the reader of a refusal like this one is entitled to know which of the two claims failed, and a
    // marking code must not become the catch-all for a document nobody signed.
    const unsigned = Uint8Array.from(receiptBytes);
    const last = unsigned.length - 1;
    unsigned[last] = (unsigned[last] ?? 0) ^ 0x01;
    const notAuthentic = await failureFrom(async () => checkLive(unsigned, responseBytes, KEY.publicKey));
    const markingWrong = await failureFrom(async () => checkLive(receiptBytes, responseBytes, KEY.publicKey));
    expect(notAuthentic.code).toBe('INVALID_SIGNATURE');
    expect(markingWrong.code).toBe('MARK_MISMATCH');
  });

  it('refuses a response carrying the marked shape twice, because the rule names exactly one', async () => {
    const responseBytes = utf8(markedBody(memberText(FAKE_IAT), memberText(FAKE_IAT + 60)));
    const receiptBytes = receiptOver(responseBytes, { sch: 'provenance-v1', d: hashRequest(utf8(memberText(FAKE_IAT))) });
    const failure = await failureFrom(async () => checkLive(receiptBytes, responseBytes, KEY.publicKey));
    expect(failure.code).toBe('MARK_MISMATCH');
    expect(failure.message).toContain('2 regions');
  });

  it('refuses an upstream mark on a deployment that attests none', async () => {
    const responseBytes = utf8(markedBody(memberText(FAKE_IAT)));
    const receiptBytes = receiptOver(responseBytes, { sch: 'none', d: hashRequest(emptyRegion()) });
    const failure = await failureFrom(async () => checkLive(receiptBytes, responseBytes, KEY.publicKey));
    expect(failure.code).toBe('MARK_MISMATCH');
  });

  it('accepts the empty region over a response that carries no mark', () => {
    const responseBytes = utf8('{"id":"chatcmpl-handbuilt","object":"chat.completion","choices":[]}');
    checkLive(receiptOver(responseBytes, { sch: 'none', d: hashRequest(emptyRegion()) }), responseBytes, KEY.publicKey);
  });

  it('checks the marking claim of a receipt that states its disclosures as well as its mark', async () => {
    // The step that decides this is taken because the payload names `mk`, and not because of the number
    // the document wears. The half below that refuses is the reason: a receipt signed over a response
    // whose marked region digests elsewhere passes the signature, the nonce, both digests, the clock and
    // the pins, and answers verified with the required step never run. Skip the step for a document that
    // also carries `sd`, `cva` and `itm` and this case stops refusing, because nothing else about the
    // bytes moves.
    const responseBytes = utf8(markedBody(memberText(FAKE_IAT)));
    const attested: Marking = { sch: 'provenance-v1', d: hashRequest(utf8(memberText(FAKE_IAT))) };
    const mismatched: Marking = { sch: 'provenance-v1', d: hashRequest(utf8(memberText(FAKE_IAT + 60))) };

    const failure = await failureFrom(async () =>
      checkLive(receiptOver(responseBytes, mismatched), responseBytes, KEY.publicKey),
    );
    expect(failure.name).toBe('ReceiptError');
    expect(failure.code).toBe('MARK_MISMATCH');
    expect(failure.message).toContain('mk.d');

    // The same document with the region it does attest: the step runs, the region matches, and the
    // receipt verifies. A case that only showed the refusal would not tell a widened check that
    // refused everything apart from a correct one.
    const verified = checkLive(receiptOver(responseBytes, attested), responseBytes, KEY.publicKey);
    expect(verified.payload.v).toBe(1);
    expect(verified.payload).toMatchObject({ mk: { sch: 'provenance-v1' } });
  });

  it('refuses bytes handed for the marking check that the receipt does not attest, even when a region in them digests right', async () => {
    // A client derives its digest and its marking check from one array, so this pairing is not a
    // convention it has to keep: a caller that supplies the attested digest and some other marked
    // bytes is refused rather than graded on the wrong response.
    const attested = utf8(markedBody(memberText(FAKE_IAT)));
    const substituted = utf8(markedBody(memberText(FAKE_IAT + 60)));
    const receiptBytes = receiptOver(attested, { sch: 'provenance-v1', d: hashRequest(utf8(memberText(FAKE_IAT + 60))) });
    const failure = await failureFrom(async () =>
      checkLive(receiptBytes, substituted, KEY.publicKey, hashRequest(attested)),
    );
    expect(failure.code).toBe('RESPONSE_HASH_MISMATCH');
    expect(failure.message).toContain('marking check');
  });
});
