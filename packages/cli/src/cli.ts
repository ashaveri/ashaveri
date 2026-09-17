#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { escapeInvisible, UsageError } from './usage.js';
import { runKeygen } from './commands/keygen.js';
import { runCredential } from './commands/credential.js';
import { runAccessLog } from './commands/accesslog.js';
import { runVerify } from './commands/verify.js';

const COMMANDS = ['verify', 'keygen', 'credential', 'accesslog'] as const;

const USAGE = `ashaveri - offline verification of dStack confidential-VM attestations, and the
operator commands for the gateway's credential file and access log

Usage:
  ashaveri <command> [options]

Arguments:
  ashaveri verify <attestation> [options]
  ashaveri keygen [--id <id>] [--json]
  ashaveri credential add --credentials <file> [--id <id>] [--kind pop|bearer]
                          [--scopes read,complete] [--label <text>]
                          [--rate perMinute=60,burst=120] [--public-key <b64url>] [--json]
  ashaveri credential revoke --credentials <file> --id <id> [--json]
  ashaveri credential list --credentials <file> [--json]
  ashaveri accesslog scrub --access-log <dir> --credential <id> [--now <iso>]
                          [--request <ref>] [--json]

  <attestation>      Path to a dStack VersionedAttestation file, or - for stdin.

The private key that keygen or credential add prints exists only in that terminal. --label
is the one field of the credential file that can name a person, and the gateway never writes
it anywhere; it is the field a data subject's request is about. accesslog scrub is the
erasure route for the access log, and a run that removes a record leaves a marker naming that
credential and the count it removed, because an erasure that looks identical to a gap proves
nothing. The marker also carries, for every part the run rewrote, the byte length and the
SHA-256 of the part as this run read it and of the bytes at that name when it read the part
back, so a third party holding the marker and a log nobody has written to since can recompute
the second pair with sha256sum instead of taking the count on trust. The first pair names
bytes that exist nowhere any more: it is this run's own account of what it took out.
--request is the operator's own reference for the instruction the erasure
answers, stored in the marker beside those digests: the digests say what left the volume, and
only the reference says what it was done for. A run that stops partway leaves the same marker
for the records it already removed, and names it in its refusal; when the marker itself cannot
be written, the refusal carries those counts instead, so an erasure is never reported as a run
that removed nothing. A run that removes nothing leaves no marker, so a credential with no
matching record and a scrub that never ran read the same from the directory. The scrub holds no
lock and no gateway stops writing while it runs: it reads a part, and it compares that part
with the bytes on disk in the last instant before it renames its copy over it, so a record
appended to a part between reading it and rewriting that part is caught, and the part is read
and done again up to three times. What that leaves is one append landing after the last
comparison and before the rename: those bytes are gone, they appear in no count and under no
digest, and no marker discloses them. An append that arrives after the rename is the other
case, and the ordinary one on a serving log: it stays on the volume, this run's copy is the
bytes beneath it, and the read back reports the two of them together. A part with nothing to
remove is left alone, and a part the scrub empties is deleted outright, its removals counted in
the marker beside the rest. A
part that will not hold still across three attempts is refused by name, and the parts already
done are receipted. Run it against a deployment that is not serving.
--now sets the day a marker is named for, and a marker for a day the deployment no longer keeps is
deleted by the next sweep. A day the sweep cannot name at all is refused before any record is
touched.

Verification options:
  --ark <file>       Trusted AMD root certificate (ARK), PEM or DER. Repeatable;
                     the attestation must chain to one of them.
  --ask <file>       ASK certificate, for attestations that carry no cert chain.
  --vcek <file>      VCEK certificate, for attestations that carry no cert chain.
  --intel-root <file>
                     Trusted Intel SGX root CA, PEM or DER. Repeatable. With it,
                     a TDX quote must also verify through Intel DCAP, so a quote
                     that is not signed by an authorized Intel key is rejected.
  --gpu-report <file>
                     NVIDIA SPDM measurements report to verify beside the
                     attestation. Repeatable; each report pairs with a --gpu-chain.
  --gpu-chain <file> Certificate chain a GPU report was signed under, PEM or DER.
                     Repeatable; pairs with --gpu-report by index.
  --gpu-root <file>  Trusted NVIDIA device identity root, PEM or DER. Repeatable.
                     Required with --gpu-report: nothing chains to a root the
                     command has not been told to trust.
  --report-data <hex>
                     Expected REPORT_DATA binding. A 64-byte value must match
                     exactly; a shorter value must sit at either end of the field
                     with the rest zero, which is how a guest pads a digest. With
                     --gpu-report, every device must have signed this value too.
  --expect-measurement <hex>
                     Pin the 96-hex platform launch measurement: the SEV-SNP
                     launch digest or the TDX MRTD, depending on the platform.
  --expect-compose-hash <hex>
                     Pin the 64-hex dstack compose hash the deployment was
                     started with, so a rebuilt image is rejected.
  --allow-debug      Accept SEV-SNP guest policies that permit debugging.

Credential and log options:
  --credentials <file>
                     The credential file a credential command reads and rewrites. The write
                     goes to a temporary name in the same directory and is renamed over the
                     original, because the gateway re-reads the file when its mtime moves.
  --access-log <dir> Directory the gateway writes its access log into.
  --credential <id>  accesslog scrub: whose records are erased.
  --request <ref>    accesslog scrub: your own reference for the instruction the erasure answers, a
                     note number or a ticket, stored in the marker beside the digests of what it
                     removed. The marker can say which bytes left the volume and only you can say who
                     asked; a removal with no reference beside it reads the same as one with no
                     authority. Up to 200 characters, kept trimmed, and stored as null when given
                     nothing, so a marker is always asked the question.
  --id <id>          Credential id, [A-Za-z0-9_-]{1,64}. Defaults to pop-<8> or bearer-<8>,
                     the prefixes the gateway's own generator uses.
  --kind pop|bearer  credential add: proof of possession, or a bearer secret. Default pop.
  --scopes <list>    credential add: comma-separated subset of read,complete. Default both.
  --rate <spec>      credential add: perMinute=60,burst=120, the budget this credential is
                     held to instead of the deployment default.
  --label <text>     credential add: free text naming the principal. Nothing else records it.
  --public-key <b64url>
                     credential add: enroll a key made by keygen or by any other tool, so the
                     private half never passes through this program. Base64url includes a dash in
                     its alphabet, and an argument that starts with one is not read as this
                     option's value, so pass such a key as --public-key=<value>.

Options for every command:
  --now <iso>        The clock the command stamps with, instead of the wall clock: the
                     verification time for verify, the whole-second createdAt or revokedAt of
                     a credential record for credential add and revoke, and the day a scrub
                     marker is named for in accesslog scrub.
  --json             Machine-readable output for every command: the verification result, a
                     credential listing or the record just touched, a scrub's counts and its
                     marker name. On keygen and credential add the object carries the one-time
                     private half, because it exists nowhere else; on credential add the warning
                     about keeping it is written to stderr, so stdout stays something to parse.
  --version          Print the CLI version.
  --help             Print this help.

Exit codes:
  0  the command did what it was asked: an attestation verified with every --expect-* pin
     matched, a credential added or revoked, a listing printed, a scrub run
  1  verification or a pin failed, or a command met an error it was not written to expect
  2  usage or input error, including a credential file this program cannot parse. A scrub can exit 2
     having already erased records, because its refusal comes after the parts it rewrote, and on both
     of its refusal routes the numbers are in the message: counted there directly, or in the marker it
     names. Neither route turns into an object under --json, which stays a refusal on stderr, so read
     a nonzero exit from there and not from stdout.`;

function cliVersion(): string {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version?: string };
  return pkg.version ?? 'unknown';
}

/**
 * One `--now` for three commands, resolved to a clock rather than a number so a credential's two
 * stamps and a marker's day all read the same instant the operator named.
 */
function clockOf(raw: string | undefined): () => number {
  if (raw === undefined) return () => Date.now();
  const at = Date.parse(raw);
  if (Number.isNaN(at)) {
    throw new UsageError(`--now is not a valid date: ${raw}`);
  }
  return () => at;
}

async function main(argv: string[]): Promise<number> {
  let flags;
  try {
    flags = parseArgs({
      allowPositionals: true,
      args: argv,
      options: {
        ark: { type: 'string', multiple: true },
        ask: { type: 'string' },
        vcek: { type: 'string' },
        'intel-root': { type: 'string', multiple: true },
        'gpu-report': { type: 'string', multiple: true },
        'gpu-chain': { type: 'string', multiple: true },
        'gpu-root': { type: 'string', multiple: true },
        'report-data': { type: 'string' },
        'expect-measurement': { type: 'string' },
        'expect-compose-hash': { type: 'string' },
        now: { type: 'string' },
        'allow-debug': { type: 'boolean' },
        json: { type: 'boolean' },
        help: { type: 'boolean' },
        version: { type: 'boolean' },
        credentials: { type: 'string' },
        'access-log': { type: 'string' },
        credential: { type: 'string' },
        request: { type: 'string' },
        id: { type: 'string' },
        kind: { type: 'string' },
        scopes: { type: 'string' },
        rate: { type: 'string' },
        label: { type: 'string' },
        'public-key': { type: 'string' },
      },
    });
  } catch (err) {
    throw new UsageError(err instanceof Error ? err.message : String(err));
  }
  const { values, positionals } = flags;
  if (values.help) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  if (values.version) {
    process.stdout.write(`${cliVersion()}\n`);
    return 0;
  }
  const command = positionals[0];
  if (command === undefined) {
    throw new UsageError(`expected a command: ${COMMANDS.join(', ')}`);
  }
  switch (command) {
    case 'verify':
      return runVerify(positionals.slice(1), values);
    case 'keygen':
      return runKeygen(values.id, values.json === true);
    case 'credential':
      return runCredential(positionals.slice(1), values, clockOf(values.now));
    case 'accesslog':
      return runAccessLog(positionals.slice(1), values, clockOf(values.now));
    default:
      throw new UsageError(`unknown command '${command}': expected one of ${COMMANDS.join(', ')}`);
  }
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (err) {
  if (err instanceof UsageError) {
    // Every message here carries a token the caller typed or a path the operating system repeats
    // back inside its own error text, so the guard belongs at the one place a refusal becomes a
    // line: escaped, the message still names what it refused, and it stays one line.
    process.stderr.write(`ashaveri: ${escapeInvisible(err.message)}\nTry 'ashaveri --help' for usage.\n`);
    process.exitCode = 2;
  } else {
    const detail = err instanceof Error ? (err.stack ?? err.message) : String(err);
    process.stderr.write(`ashaveri: unexpected error: ${detail}\n`);
    process.exitCode = 1;
  }
}
