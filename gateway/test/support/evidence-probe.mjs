// The customer's own reading of one store directory, in a process that is not the one that served it.
//
// JavaScript rather than the suite's TypeScript because a child runs outside the runner's transpiler, the
// same reason `store-owner-probe.mjs` and the CLI cases read `dist/`: a checkpoint read this way is taken
// by a second process, which is what makes it evidence rather than a number the serving process chose to
// print. It exits, and with it goes the claim its opening filed, so the directory is free for the next
// start.
//
// argv: <dir> <retentionJson> <declarationJson> [sidecarIndex]
//   retentionJson    {"maxAgeSeconds":n,"maxCount":n,"source":{"name","uncertaintySeconds","instant"}}
//   declarationJson  the scope the customer declares: subject, duty, period, intake, expectedHead,
//                    maxIntervalSeconds, excludes
// One line of JSON answers: {"ok":true,"evidence":...} or {"ok":false,"code","message"}.
import { readRetentionEvidence } from '../../dist/retention-evidence.js';

const [dir, retentionJson, declarationJson, sidecar] = process.argv.slice(2);
const answer = { ok: false, code: null, message: null, evidence: null };
try {
  const stated = JSON.parse(retentionJson);
  const time = stated.source;
  const retention = {
    maxAgeSeconds: stated.maxAgeSeconds ?? undefined,
    maxCount: stated.maxCount ?? undefined,
    time: { name: time.name, uncertaintySeconds: time.uncertaintySeconds, nowSeconds: () => time.instant },
  };
  const evidence = await readRetentionEvidence({
    dir,
    retention,
    sidecarIndex: sidecar === 'true',
    ...JSON.parse(declarationJson),
  });
  answer.ok = true;
  answer.evidence = evidence;
} catch (error) {
  answer.code = typeof error?.code === 'string' ? error.code : null;
  answer.message = error instanceof Error ? error.message : String(error);
}
process.stdout.write(`${JSON.stringify(answer)}\n`);
process.exit(answer.ok ? 0 : 1);
