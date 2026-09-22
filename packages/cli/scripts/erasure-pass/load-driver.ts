import { Agent, request } from 'node:http';
import { sha256Hex, signPopAuthorization, toBase64Url } from '@ashaveri/receipt';

/**
 * The load, and what it measures.
 *
 * Requests are issued on an absolute schedule rather than one after another: a caller that waits for a
 * response before sending the next request would measure its own patience, and the whole point here is
 * the queue a serving process builds while it is busy with something else. So the rate is fixed in
 * advance, a request is fired when its instant arrives whether or not the last one has come back, and
 * what a sample records is the time from that scheduled instant to the last byte of the answer. A stalled
 * loop therefore shows up as latency rather than as a slower sender, which is exactly how it shows up to
 * a client on the other side of a network.
 *
 * This runs in the harness process, not in the one being measured. Signing and hashing every request are
 * work the serving loop never sees, which is the point.
 */
export interface Sample {
  /** Both clocks are `performance.now()` in the harness process, so a duration needs no conversion. */
  issuedAt: number;
  endedAt: number;
  status: number;
}

export interface DriverOptions {
  port: number;
  credentialId: string;
  secretKey: Uint8Array;
  perSecond: number;
  body: string;
  target: string;
}

export interface Driver {
  start(): void;
  stop(): Promise<void>;
  /** Everything issued so far, in the order it was issued. */
  samples(): readonly Sample[];
  /** Any response that was not the completion it asked for, or that never arrived. */
  failures(): readonly string[];
  /** The most requests outstanding at any one instant, which is the queue this driver let build up. */
  peakInFlight(): number;
}

/** A nonce per request: this driver's own marker and a counter, so no two presentations collide. */
function nonceAt(at: number): Uint8Array {
  const nonce = new Uint8Array(16).fill(0x4d, 0, 12);
  nonce[12] = (at >>> 24) & 0xff;
  nonce[13] = (at >>> 16) & 0xff;
  nonce[14] = (at >>> 8) & 0xff;
  nonce[15] = at & 0xff;
  return nonce;
}

/**
 * Counted across drivers, not within one.
 *
 * The gateway remembers every nonce a credential has presented, and this harness makes a fresh driver per
 * measurement window while one serving process answers all of them. A counter that started again with each
 * driver would hand the second window the nonces the first had already spent, and the second window would
 * measure a queue of refusals.
 */
let presented = 0;

export function createDriver(options: DriverOptions): Driver {
  const digest = sha256Hex(new TextEncoder().encode(options.body));
  const samples: Sample[] = [];
  const failures: string[] = [];
  const agent = new Agent({ keepAlive: true, maxSockets: 2048 });
  let inFlight = 0;
  let peak = 0;
  let issued = 0;
  let running = false;
  let timer: NodeJS.Timeout | null = null;
  let settled: (() => void) | null = null;

  function send(): void {
    issued += 1;
    presented += 1;
    const nonce = nonceAt(presented);
    const headers = {
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(options.body, 'utf8')),
      authorization: signPopAuthorization(
        {
          // The stamp is the wall clock, as a real client's is: this run lasts minutes, and a pinned
          // instant would be refused as stale a few seconds in.
          ts: Math.floor(Date.now() / 1000),
          nonce,
          method: 'POST',
          target: options.target,
          bodyDigestHex: digest,
        },
        options.credentialId,
        options.secretKey,
      ),
      'x-ashaveri-nonce': toBase64Url(nonce),
    };
    const issuedAt = performance.now();
    inFlight += 1;
    if (inFlight > peak) peak = inFlight;
    const response = request(
      { host: '127.0.0.1', port: options.port, path: options.target, method: 'POST', agent, headers },
      (res) => {
        const status = res.statusCode ?? 0;
        // The body is read to the end and dropped: a completion nobody drains is a response the gateway
        // is still writing, and the next request would be measured behind it.
        res.on('data', () => undefined);
        res.on('end', () => {
          inFlight -= 1;
          const endedAt = performance.now();
          samples.push({ issuedAt, endedAt, status });
          if (status !== 200) failures.push(`status ${String(status)}`);
          checkDone();
        });
        res.on('aborted', () => {
          inFlight -= 1;
          failures.push('aborted response');
          checkDone();
        });
      },
    );
    response.on('error', (error) => {
      inFlight -= 1;
      failures.push(error.message);
      checkDone();
    });
    response.end(options.body, 'utf8');
  }

  function checkDone(): void {
    if (running || inFlight > 0 || settled === null) return;
    settled();
    settled = null;
  }

  return {
    start(): void {
      running = true;
      const spacingMs = 1000 / options.perSecond;
      const startedAt = performance.now() + spacingMs;
      const schedule = (): void => {
        if (!running) return;
        send();
        const next = startedAt + issued * spacingMs;
        const delay = Math.max(0, next - performance.now());
        timer = setTimeout(schedule, delay);
      };
      timer = setTimeout(schedule, Math.max(0, startedAt - performance.now()));
    },
    async stop(): Promise<void> {
      running = false;
      if (timer !== null) clearTimeout(timer);
      if (inFlight === 0) return;
      await new Promise<void>((resolve) => {
        settled = resolve;
      });
    },
    samples(): readonly Sample[] {
      return samples;
    },
    failures(): readonly string[] {
      return failures;
    },
    peakInFlight(): number {
      return peak;
    },
  };
}

/**
 * Every sample whose request was scheduled inside the window, and nothing else.
 *
 * A sample is placed by when it was sent rather than by when it came back: a request sent into a blocked
 * loop is the case being measured, and selecting on the answer's arrival would keep the samples that
 * happened to slip out before the stall and drop the ones that waited for all of it.
 */
export function windowSamples(samples: readonly Sample[], from: number, to: number): number[] {
  const durations: number[] = [];
  for (const each of samples) {
    if (each.issuedAt >= from && each.issuedAt < to) durations.push(each.endedAt - each.issuedAt);
  }
  return durations;
}
