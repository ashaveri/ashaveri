import { afterEach, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { once } from 'node:events';
import { GuestClient, GuestError } from '../src/guest.js';
import { fromHex, toHex } from '../src/digest.js';

/**
 * The agent speaks plain JSON over a socket, so an HTTP listener on loopback
 * exercises the same wire path the CVM's Unix socket does.
 */
type Handler = (
  path: string,
  body: Record<string, unknown>,
) => { status?: number; json?: unknown; text?: string; hang?: true };

const servers: Server[] = [];

afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.close();
    await once(server, 'close');
  }
});

async function agent(handler: Handler): Promise<string> {
  const server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as Record<string, unknown>;
      const result = handler(request.url ?? '', body);
      if (result.hang === true) {
        return;
      }
      response.statusCode = result.status ?? 200;
      if (result.text !== undefined) {
        response.setHeader('content-type', 'text/html');
        response.end(result.text);
        return;
      }
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify(result.json ?? {}));
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  servers.push(server);
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

function client(endpoint: string, timeoutMs?: number): GuestClient {
  return new GuestClient({ endpoint, timeoutMs });
}

async function expectCode(fn: () => Promise<unknown>, code: GuestError['code']): Promise<string> {
  try {
    await fn();
  } catch (error) {
    expect(error).toBeInstanceOf(GuestError);
    expect((error as GuestError).code).toBe(code);
    return (error as Error).message;
  }
  throw new Error(`expected GuestError ${code}, but the call succeeded`);
}

describe('GuestClient key derivation', () => {
  it('sends the path, purpose and algorithm and decodes hex material', async () => {
    let seen: { path: string; body: Record<string, unknown> } | null = null;
    const endpoint = await agent((path, body) => {
      seen = { path, body };
      return { json: { key: '11'.repeat(32), signature_chain: ['aabb', 'ccdd'] } };
    });
    const key = await client(endpoint).getKey('/ashaveri/receipt', 'v1', 'ed25519');
    expect(seen).toEqual({ path: '/GetKey', body: { path: '/ashaveri/receipt', purpose: 'v1', algorithm: 'ed25519' } });
    expect(toHex(key.key)).toBe('11'.repeat(32));
    expect(key.signatureChain.map(toHex)).toEqual(['aabb', 'ccdd']);
  });

  it('rejects a response whose key is missing or not hex', async () => {
    const noKey = await agent(() => ({ json: { signature_chain: [] } }));
    await expectCode(() => client(noKey).getKey('/k', '', 'ed25519'), 'GUEST_MALFORMED_RESPONSE');
    const badHex = await agent(() => ({ json: { key: 'zz', signature_chain: [] } }));
    await expectCode(() => client(badHex).getKey('/k', '', 'ed25519'), 'GUEST_MALFORMED_RESPONSE');
    const badChain = await agent(() => ({ json: { key: 'aa', signature_chain: 'nope' } }));
    await expectCode(() => client(badChain).getKey('/k', '', 'ed25519'), 'GUEST_MALFORMED_RESPONSE');
  });
});

describe('GuestClient evidence', () => {
  it('posts report_data as hex and returns the document bytes', async () => {
    const reportData = fromHex('ab'.repeat(32));
    let posted: Record<string, unknown> | null = null;
    const endpoint = await agent((_path, body) => {
      posted = body;
      return { json: { attestation: toHex(Uint8Array.from([1, 2, 3])) } };
    });
    const document = await client(endpoint).attest(reportData);
    expect(posted).toEqual({ report_data: 'ab'.repeat(32) });
    expect(document).toEqual(Uint8Array.from([1, 2, 3]));
  });

  it('refuses report data the platform field cannot hold, without a request', async () => {
    const endpoint = await agent(() => ({ json: { attestation: 'ff' } }));
    await expectCode(() => client(endpoint).attest(new Uint8Array(0)), 'GUEST_MALFORMED_RESPONSE');
    await expectCode(() => client(endpoint).attest(new Uint8Array(65)), 'GUEST_MALFORMED_RESPONSE');
  });

  it('surfaces an agent error object as an RPC failure', async () => {
    const endpoint = await agent(() => ({ json: { error: 'report_data is required' } }));
    const message = await expectCode(() => client(endpoint).attest(new Uint8Array(32)), 'GUEST_RPC_ERROR');
    expect(message).toContain('report_data is required');
  });

  it('reports a non-JSON body with the status that produced it', async () => {
    const endpoint = await agent(() => ({ status: 502, text: '<html>bad gateway</html>' }));
    const message = await expectCode(() => client(endpoint).attest(new Uint8Array(32)), 'GUEST_MALFORMED_RESPONSE');
    expect(message).toContain('status 502');
  });

  it('fails the call rather than hanging when the agent stops answering', async () => {
    const endpoint = await agent(() => ({ hang: true }));
    const message = await expectCode(
      () => client(endpoint, 40).getKey('/k', '', 'ed25519'),
      'GUEST_REQUEST_FAILED',
    );
    expect(message).toContain('did not answer');
  });
});

describe('GuestClient Info', () => {
  it('parses tcb_info out of the JSON string the agent wraps it in', async () => {
    const endpoint = await agent(() => ({ json: { tcb_info: '{"tcb_level":4}' } }));
    const info = await client(endpoint).info();
    expect(info.tcbInfo).toEqual({ tcb_level: 4 });
  });

  it('rejects missing or unparseable tcb_info', async () => {
    const missing = await agent(() => ({ json: {} }));
    await expectCode(() => client(missing).info(), 'GUEST_MALFORMED_RESPONSE');
    const broken = await agent(() => ({ json: { tcb_info: 'not json' } }));
    await expectCode(() => client(broken).info(), 'GUEST_MALFORMED_RESPONSE');
  });
});

describe('GuestClient endpoint resolution', () => {
  it('fails when no socket and no simulator endpoint is configured', () => {
    const previous = process.env['DSTACK_SIMULATOR_ENDPOINT'];
    delete process.env['DSTACK_SIMULATOR_ENDPOINT'];
    try {
      expect(() => new GuestClient()).toThrow(/no dstack guest socket/);
    } finally {
      if (previous !== undefined) {
        process.env['DSTACK_SIMULATOR_ENDPOINT'] = previous;
      }
    }
  });

  it('prefers DSTACK_SIMULATOR_ENDPOINT over probing for sockets', async () => {
    const previous = process.env['DSTACK_SIMULATOR_ENDPOINT'];
    const endpoint = await agent(() => ({ json: { attestation: 'ff' } }));
    process.env['DSTACK_SIMULATOR_ENDPOINT'] = endpoint;
    try {
      expect(await new GuestClient().attest(new Uint8Array(32))).toEqual(Uint8Array.from([0xff]));
    } finally {
      if (previous === undefined) {
        delete process.env['DSTACK_SIMULATOR_ENDPOINT'];
      } else {
        process.env['DSTACK_SIMULATOR_ENDPOINT'] = previous;
      }
    }
  });

  it('reports an unreachable endpoint as a request failure', async () => {
    await expectCode(
      () => client('http://127.0.0.1:1').attest(new Uint8Array(32)),
      'GUEST_REQUEST_FAILED',
    );
  });
});
