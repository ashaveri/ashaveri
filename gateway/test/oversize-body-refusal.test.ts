import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { generated, harness, type Harness } from './helpers.js';

const CREDENTIAL = 'oversize';
const MODEL = 'mock-model-1';
/** The bound these two cells state, held small so a case about the bound costs kilobytes and not megabytes. */
const LIMIT_BYTES = 4096;
/** What a run that states no bound reads, repeated here as the number the refusal has to print. */
const SHIPPED_LIMIT_BYTES = 16 * 1024 * 1024;

/** A body of whole bytes, long enough to be a request rather than a header: only its length is read. */
function requestBody(bytes: number): string {
  const head = `{"model":"${MODEL}","messages":[{"role":"user","content":"`;
  const tail = `"}]}`;
  return head + 'x'.repeat(bytes - head.length - tail.length) + tail;
}

/** The route's own refusal shape, as the cells below demand it. */
interface RefusalBody {
  readonly error?: { readonly message?: string; readonly type?: string; readonly code?: string };
}

interface Answer {
  readonly statusCode: number;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly json: () => RefusalBody;
}

function refusalOf(answer: Answer): RefusalBody['error'] {
  return answer.json().error;
}

async function gatewayReading(bytes: number): Promise<Harness> {
  return await harness({
    credentials: [generated(CREDENTIAL, ['complete', 'read'])],
    gateway: { requestBodyLimitBytes: bytes },
  });
}

/**
 * A completion the pipeline would have served, apart from its length: signed over the exact bytes it sends,
 * because a refusal for size that arrived only for an unauthenticated request would say nothing about where
 * in the run the bound is taken.
 */
async function send(h: Harness, body: string): Promise<Answer> {
  const target = '/v1/chat/completions';
  return (await h.app.inject({
    method: 'POST',
    url: target,
    headers: { 'content-type': 'application/json', ...h.signFor(CREDENTIAL, 'POST', target, body) },
    payload: body,
  })) as unknown as Answer;
}

describe('an oversize request body', () => {
  it('refuses a declared content-length past the bound, before reading it, in the shape the route refuses in', async () => {
    const h = await gatewayReading(LIMIT_BYTES);
    const body = requestBody(LIMIT_BYTES + 512);
    const answer = await send(h, body);
    expect(answer.statusCode, 'bytes past the bound this process reads are refused').toBe(413);
    expect(refusalOf(answer)).toMatchObject({
      type: 'invalid_request_error',
      code: 'BODY_TOO_LARGE',
      message: expect.stringContaining(String(LIMIT_BYTES)),
    });
    expect(refusalOf(answer)?.message, 'the answer says what the bound is a setting of').toContain(
      'ASHAVERI_REQUEST_BODY_LIMIT_BYTES',
    );
    expect(answer.headers['x-ashaveri-receipt-id'], 'a refusal for size issues nothing').toBeUndefined();
    // The record is written even though no route ran: the arrival is stamped in `onRequest`, and the answer
    // reaches the log through the same finish the response does. Without this line the 413 could stop being
    // recorded and every cell above would still pass.
    expect(
      h.log.entries().filter((entry) => entry.p === '/v1/chat/completions'),
      'the access line carries the refusal this process answered with',
    ).toMatchObject([{ st: 413, cred: null, deny: null }]);
  });

  it('refuses a body that passes the bound while it is being read, with the one answer', async () => {
    const h = await gatewayReading(LIMIT_BYTES);
    const chunk = LIMIT_BYTES / 2;
    const answer = (await h.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      // A stream body carries no `Content-Length`, so nothing here is known about the size until a chunk of
      // it arrives: this is the arm where the bound is met by the reader rather than by the header.
      headers: { 'content-type': 'application/json' },
      payload: Readable.from([Buffer.from(requestBody(chunk)), Buffer.from(requestBody(chunk)), Buffer.from(requestBody(chunk))]),
    })) as unknown as Answer;
    expect(answer.statusCode, 'a body that grows past the bound is refused while it is read').toBe(413);
    expect(refusalOf(answer)).toMatchObject({
      type: 'invalid_request_error',
      code: 'BODY_TOO_LARGE',
      message: expect.stringContaining(String(LIMIT_BYTES)),
    });
    expect(answer.headers['x-ashaveri-receipt-id'], 'the second shape issues nothing either').toBeUndefined();
  });

  it('names the bound a run that stated none reads', async () => {
    const h = await harness({ credentials: [generated(CREDENTIAL, ['complete', 'read'])] });
    const answer = (await h.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: {
        'content-type': 'application/json',
        // The header is the whole of the request this cell needs: a declared length past the bound is
        // refused before a byte is read, so the shipped figure is proved without sending sixteen megabytes.
        'content-length': String(SHIPPED_LIMIT_BYTES + 1),
        ...h.signFor(CREDENTIAL, 'POST', '/v1/chat/completions', null),
      },
    })) as unknown as Answer;
    expect(answer.statusCode, 'the bound a run that named nothing holds is the shipped one').toBe(413);
    expect(refusalOf(answer)?.message, 'and the answer prints it').toContain(String(SHIPPED_LIMIT_BYTES));
  });

  it('reads the bound the environment states, ahead of the one it ships', async () => {
    process.env['ASHAVERI_REQUEST_BODY_LIMIT_BYTES'] = String(LIMIT_BYTES * 2);
    try {
      const h = await harness({ credentials: [generated(CREDENTIAL, ['complete', 'read'])] });
      const answer = await send(h, requestBody(LIMIT_BYTES * 2 + 512));
      expect(answer.statusCode, 'a body past the stated bound is refused').toBe(413);
      expect(refusalOf(answer)?.message, 'and the answer prints the stated number, not the shipped one').toContain(
        String(LIMIT_BYTES * 2),
      );
      const kept = await send(h, requestBody(LIMIT_BYTES + 512));
      expect(kept.statusCode, 'a body past the shipped bound but inside the stated one is read').not.toBe(413);
    } finally {
      delete process.env['ASHAVERI_REQUEST_BODY_LIMIT_BYTES'];
    }
  });

  // Precedence is documented in `docs/configured-values.md`, so the order has to be asserted and not assumed:
  // swapping the two reads in `server.ts` would otherwise leave every other cell here green.
  it('keeps the bound the option states when the environment states another', async () => {
    process.env['ASHAVERI_REQUEST_BODY_LIMIT_BYTES'] = String(LIMIT_BYTES);
    try {
      const h = await harness({
        credentials: [generated(CREDENTIAL, ['complete', 'read'])],
        gateway: { requestBodyLimitBytes: LIMIT_BYTES * 4 },
      });
      try {
        const inside = await send(h, requestBody(LIMIT_BYTES + 512));
        expect(inside.statusCode, 'a body past the environment number but inside the option is read').not.toBe(413);
        const over = await send(h, requestBody(LIMIT_BYTES * 4 + 512));
        expect(over.statusCode, 'the option is the bound this process holds').toBe(413);
        expect(refusalOf(over)?.message, 'and the refusal prints the option, never the environment').toContain(
          String(LIMIT_BYTES * 4),
        );
      } finally {
        await h.app.close();
      }
    } finally {
      delete process.env['ASHAVERI_REQUEST_BODY_LIMIT_BYTES'];
    }
  });

  it('refuses to build on a bound the environment states badly, rather than serving the shipped one', async () => {    process.env['ASHAVERI_REQUEST_BODY_LIMIT_BYTES'] = 'not-a-bound';
    try {
      await expect(
        harness({ credentials: [generated(CREDENTIAL, ['complete', 'read'])] }),
        'a deployment that believes it set a number is not run on another',
      ).rejects.toThrow(/positive whole number of bytes/u);
    } finally {
      delete process.env['ASHAVERI_REQUEST_BODY_LIMIT_BYTES'];
    }
  });

  it('hands back every error it was not asked to answer', async () => {
    const h = await gatewayReading(LIMIT_BYTES);
    const answer = (await h.app.inject({
      method: 'POST',
      url: '/v1/chat/completions',
      headers: { 'content-type': 'application/csv' },
      payload: '{"model":"x"}',
    })) as unknown as Answer;
    // The handler above answers one framework error and nothing else, so a media type this gateway does not
    // parse keeps the answer the shipped handler gives it: a top-level code, and no refusal in the route's
    // shape. Pinning this is what keeps the handler from quietly becoming the answer to every failure.
    expect(answer.statusCode).toBe(415);
    const body = answer.json() as unknown as { readonly code?: string; readonly error?: unknown };
    expect(body.code, 'the shipped handler answers with its own code').toBe('FST_ERR_CTP_INVALID_MEDIA_TYPE');
    // The shipped serialization carries the status text where this gateway carries an envelope, so the two
    // answers are told apart by what `error` holds: a word for the status, and not `{message, type, code}`.
    expect(body.error, 'and writes no refusal envelope of this route over it').toBe('Unsupported Media Type');
  });
});
