#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { buildGateway } from './server.js';

const USAGE = `signerd - receipt-signing gateway for Ashaveri verifiable inference

Usage:
  signerd --mock [--host <host>] [--port <port>]

Options:
  --mock          Run in mock mode: deterministic completions, dev signing key,
                  no TEE. This is the only mode in the current build.
  --host <host>   Bind address. Default: 127.0.0.1.
  --port <port>   Bind port. Default: 7173.
  --help          Print this help.`;

const { values } = parseArgs({
  options: {
    mock: { type: 'boolean' },
    host: { type: 'string', default: '127.0.0.1' },
    port: { type: 'string', default: '7173' },
    help: { type: 'boolean' },
  },
});

if (values.help) {
  process.stdout.write(`${USAGE}\n`);
  process.exit(0);
}
if (!values.mock) {
  process.stderr.write("signerd: only --mock is supported in this build\nTry 'signerd --help' for usage.\n");
  process.exit(2);
}

const app = buildGateway({});
const port = Number(values.port);
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  process.stderr.write(`signerd: invalid port '${String(values.port)}'\n`);
  process.exit(2);
}
const host = values.host as string;

await app.listen({ port, host });
process.stdout.write(`signerd (mock) listening on http://${host}:${port}\n`);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    void app.close().then(() => process.exit(0));
  });
}
