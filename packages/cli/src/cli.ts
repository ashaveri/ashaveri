#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { escapeInvisible, UsageError } from './usage.js';
import { runKeygen } from './commands/keygen.js';
import { runCredential } from './commands/credential.js';
import { runAccessLog } from './commands/accesslog.js';
import { runVerify } from './commands/verify.js';
import { runVerifyReceipt } from './commands/verify-receipt.js';

const COMMANDS = ['verify', 'verify-receipt', 'keygen', 'credential', 'accesslog'] as const;

const USAGE = `ashaveri - offline verification of dStack confidential-VM attestations and of published
receipts, and the operator commands for the gateway's credential file and access log

Usage:
  ashaveri <command> [options]

Arguments:
  ashaveri verify <attestation> [options]
  ashaveri verify-receipt <receipt> --policy <file> --manifest <file> --nonce <hex>
                         [--manifest-key <b64url>]...
                         [--request-body <file> | --request-hash <hex>]
                         [--response-body <file> | --response-hash <hex>] [options]
  ashaveri keygen [--id <id>] [--json]
  ashaveri credential add --credentials <file> [--id <id>] [--kind pop|bearer]
                          [--scopes read,complete] [--label <text>]
                          [--rate perMinute=60,burst=120] [--public-key <b64url>] [--json]
  ashaveri credential revoke --credentials <file> --id <id> [--json]
  ashaveri credential list --credentials <file> [--json]
  ashaveri accesslog scrub --access-log <dir> --credential <id> [--now <iso>]
                          [--request <ref>] [--json]

  <attestation>      Path to a dStack VersionedAttestation file, or - for stdin.
  <receipt>          Path to a COSE_Sign1 receipt file, or - for stdin.

verify-receipt reaches a verdict about a receipt from the files in front of it: the receipt, the
policy that names what is trusted, the deployment manifest that declares the signing key, and the
request and response the receipt attests. It makes no request of any kind. The manifest is read from
--manifest and never fetched, and the transport these checks run over refuses every route but that
one file, so a receipt whose att.url names a host does not make this command reach that host. A key
that signs the manifest is the one trust a policy file cannot carry, so --manifest-key names it for
one run instead, and the report says in both of its shapes which keys it checked a seal against and
that the cited policy digest covers none of them. What it applies is what a client applies: the same
verification rules, in the same order, from the same package, over a receipt taken out of a response
header and put on a disk. What it does not do is read
the evidence document behind att.d, which no file here stands in for; the receipt's own att.ts still
has to sit inside the policy's evidence window, and the report says in terms that the document was not
fetched. A v1 receipt attests the digest of a response, which --response-hash can carry. A v2 receipt
attests one region inside those bytes, which needs --response-body, because the digest of a region
nobody handed over is not a check. --now is the verification time, and it is how an archived receipt
is read at all: the policy's windows close against it, so judging last year's receipt by today's
clock is a refusal with a code rather than a verdict, which is the honest answer to a question about
a replay.

The private key that keygen or credential add prints exists only in that terminal. --label
is the one field of the credential file that can name a person, and the gateway never writes
it anywhere; it is the field a data subject's request is about. accesslog scrub is the erasure
route for the access log, and a run that removes a record leaves a marker naming that credential
and the count it removed, because an erasure that looks identical to a gap proves nothing. The
marker also carries, for every part the run rewrote or deleted, the byte length and the SHA-256 of
the part as this run read it and of the bytes at that name when it read the part back. Only the
second pair is something a third party can check, and only with a log nobody has written to since:
where a part is still there to read, sha256sum of the file in front of them should answer with it,
which ties this run's count to that file rather than to a claim about some other one. A part that
is no longer there at all is given the empty file's pair, which is true of the name and is not a
checksum of anything. The first pair names bytes that exist nowhere any more: it is this run's own
account of what it took out, and nothing but this run's word connects it to a number. The printed
line gives the count of records taken out and the tally of parts this run rewrote or deleted, and
those two are not the same measure: a part whose records came back is in the tally and adds nothing
to the count. --request is the operator's own reference for the instruction the erasure answers,
stored in the marker beside those digests: the digests say what left the volume, and only the
reference says what it was done for. Three routes refuse after bytes have already left, and each of
them says which: a run that stops partway leaves the marker for the parts it already finished and
names it in its refusal; a run whose own marker cannot be written carries those counts in the
refusal instead; and a run that published a part and can no longer read that name back files
nothing and gives that part's count in its own sentence, because no other line will ever carry it.
So an erasure is never reported as a run that removed nothing, and never reported as one that left
a receipt it did not write. A run that rewrote and deleted no part leaves no marker, so a
credential with no matching record and a scrub that never ran read the same from the directory. The
scrub holds no lock and no gateway stops writing while it runs: it reads a part, and it compares
that part with the bytes on disk in the last instant before it renames its copy over it, so a
record appended to a part between reading it and rewriting that part is caught, and the part is
read and done again up to three times. What that leaves is an append landing after the last
comparison and before the rename, and nothing bounds how many of them a moment can hold: those
bytes are gone, they appear in no count and under no digest, and no marker discloses them. An
append that arrives after the rename is the other case, and the ordinary one on a serving log: it
stays on the volume, this run's copy is the bytes beneath it, and the read back reports the two of
them together. A part with nothing to remove is left alone, and a part the scrub empties is
deleted outright, its removals counted in the marker beside the rest. A part that a second name
also holds, through a hard link or a symlink, is refused before this run writes, renames or deletes
anything at it: this run empties one name and the records would stand at the other, and a marker
claiming they left the volume would be the one thing this command exists not to write. A shared
name this run can read is left alone when it holds none of the subject's records; a link whose
target this run cannot read at all is refused by name, whoever that link belongs to. A part that
will not hold still across three attempts is refused by name, and the parts already done are
receipted. Run it against a deployment that is not serving. --now sets the day a marker is named
for, and a marker for a day the deployment no longer keeps is deleted by the next sweep. A day
the sweep cannot name at all is refused before any record is touched.

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
  --policy <file>    Take the trust anchors and the platform measurement pin from
                     a policy document instead of naming them here, and print the
                     digest that document hashes to, so a run can be cited by the
                     policy it enforced rather than by the flags someone typed.
                     Refused together with --ark, --intel-root, --gpu-root,
                     --expect-measurement and --expect-compose-hash: a file and a
                     flag pinning one thing leave the printed digest describing a
                     check that did not run. Anchor paths in the document are read
                     against the directory holding it, either separator, and a
                     family the document leaves out accepts the roots bundled with
                     this verifier. The receipt pins a document carries - issuers,
                     instances, keys, age windows - are applied by verify-receipt,
                     which reads the same file through the same loader and prints the
                     same digest; verify itself neither applies nor relaxes them,
                     because what it judges is an attestation, not a receipt.
  --allow-debug      Accept SEV-SNP guest policies that permit debugging.

Receipt verification options:
  --manifest <file>  The deployment manifest that declares the receipt signing key, as a file. This
                     command fetches no manifest, and a key the manifest does not declare is refused
                     whatever the policy pins, because the two are meant to say the same thing.
  --manifest-key <b64url>
                     A key this deployment's manifest was signed with, as the base64url of its 32
                     public bytes. Repeatable, one key per flag: this run checks the seal on the
                     manifest against the keys it was handed here, and authenticates the document when
                     one of them holds. Designating a key cuts both ways, and that is a change of
                     verdict rather than of wording: a manifest carrying no signature at all, or one
                     made by a key nobody named, is then refused with MANIFEST_NOT_AUTHENTICATED
                     instead of being read and reported as resting on nothing, because a run that named
                     a signer and was handed no signature is looking at something other than the
                     deployment it pinned. Each key's id is computed from the key, so a designation
                     cannot type an id that its own key contradicts. A policy file has no field for a
                     manifest signing key and refuses a document naming one, so what arrives here joins
                     the policy for this run only and sits outside the digest that run cites, and the
                     report names every key it trusted and where it came from. Base64url includes a
                     dash in its alphabet, and an argument that starts with one is not read as this
                     option's value, so pass such a key as --manifest-key=<value>.
  --nonce <hex>      The challenge this receipt is checked against, as the client that made the
                     request chose it. A receipt answers one challenge, so without this the verdict
                     would be about a request nobody named.
  --request-body <file>
                     The request bytes as they were sent. The receipt's req is their SHA-256, so
                     handing over the bytes lets this command recompute the digest it compares.
  --request-hash <hex>
                     That digest itself, 64 hex, where the bytes are gone and the digest was kept.
  --response-body <file>
                     The response bytes as they were received, framing included for a streamed
                     answer. Required for a v2 receipt, whose marking claim is a digest of one region
                     read out of exactly these bytes.
  --response-hash <hex>
                     The digest of those bytes, 64 hex, which carries a v1 receipt's check but not a
                     v2 one's.

Credential and log options:
  --credentials <file>
                     The credential file a credential command reads and rewrites. The write
                     goes to a temporary name in the same directory and is renamed over the
                     original, because the gateway re-reads the file when its mtime moves.
  --access-log <dir> Directory the gateway writes its access log into.
  --credential <id>  accesslog scrub: the credential whose records the run filters out, matched on the
                     credential field the log writes per record.
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
  --now <iso>        The clock the command reads instead of the wall clock: the
                     verification time for verify and verify-receipt, the whole-second createdAt or revokedAt of
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
     matched, a receipt verified with every pin its policy names matched, a credential added or
     revoked, a listing printed, a scrub run
  1  verification or a pin failed, or a command met an error it was not written to expect
  2  usage or input error, including a credential file this program cannot parse. A scrub can exit 2
     having already erased records, because its refusal comes after the parts it rewrote, and every
     refusal route puts the numbers in the message: counted there directly, named in the marker it
     points at, or, for a part it published and can no longer read, carried in that part's own sentence.
     None of them turns into an object under --json, which stays a refusal on stderr, so read
     a nonzero exit from there and not from stdout.`;

/**
 * The version the single-file bundle carries, and only the bundle. That artifact is copied to a
 * machine with no checkout and nothing beside it, so its `--version` cannot be a read of a manifest
 * that is not there: the bundling step substitutes the string from the package it was built under,
 * and an unbundled build leaves this identifier undeclared, which `typeof` reads as absent.
 */
declare const BUNDLE_VERSION: string | undefined;

function cliVersion(): string {
  if (typeof BUNDLE_VERSION === 'string') {
    return BUNDLE_VERSION;
  }
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
        policy: { type: 'string' },
        manifest: { type: 'string' },
        'manifest-key': { type: 'string', multiple: true },
        nonce: { type: 'string' },
        'request-body': { type: 'string' },
        'request-hash': { type: 'string' },
        'response-body': { type: 'string' },
        'response-hash': { type: 'string' },
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
    case 'verify-receipt':
      return runVerifyReceipt(positionals.slice(1), values);
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
