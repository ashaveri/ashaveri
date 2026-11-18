// A child releases store ownership on exit and reads built code without the test transpiler.
// argv: <dir> <retentionJson> <declarationJson> [sidecarIndex]
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
