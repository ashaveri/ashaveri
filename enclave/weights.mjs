#!/usr/bin/env node
// Records what a deployment's weights are, so the digest a receipt carries can be
// traced back to the files the inference server actually loaded.
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';

const USAGE = `weights.mjs - build or check a weights manifest

Usage:
  weights.mjs generate <weights-dir> <manifest-out>
  weights.mjs verify <weights-dir> <manifest>

generate writes a canonical manifest listing every regular file under <weights-dir>
with its sha256, sorted by path. verify recomputes the digests from disk and fails
unless the manifest describes exactly those files, in exactly that spelling.

The gateway hashes the manifest file itself to produce the wts field of every receipt,
so only the bytes of a canonical manifest are a meaningful pin.

Exit codes:
  0  manifest generated, or verification passed
  1  verification failed
  2  usage or input error`;

class InputError extends Error {}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function digestFile(path) {
  return new Promise((resolveHash, rejectHash) => {
    const hash = createHash('sha256');
    const source = createReadStream(path);
    source.on('error', rejectHash);
    source.on('data', (chunk) => hash.update(chunk));
    source.on('end', () => resolveHash(hash.digest('hex')));
  });
}

/** The manifest describes the weights, not itself, so it is exempt from the scan. */
function relativeWithin(dir, target) {
  if (target === undefined) return null;
  const rel = relative(resolve(dir), resolve(target));
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) return null;
  return rel.split(sep).join('/');
}

async function listFiles(dir, manifestPath) {
  const skip = relativeWithin(dir, manifestPath);
  const found = [];
  async function walk(absolute, prefix) {
    const entries = await readdir(absolute, { withFileTypes: true }).catch((error) => {
      throw new InputError(`cannot read ${prefix === '' ? absolute : prefix}: ${error.message}`);
    });
    for (const entry of entries) {
      const childAbsolute = join(absolute, entry.name);
      const childRelative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (childRelative === skip) continue;
      if (entry.isSymbolicLink()) {
        throw new InputError(`${childRelative} is a symlink; weights must be plain files`);
      }
      if (entry.isDirectory()) {
        await walk(childAbsolute, childRelative);
      } else if (entry.isFile()) {
        found.push({ path: childRelative, sha256: await digestFile(childAbsolute) });
      } else {
        throw new InputError(`${childRelative} is not a regular file`);
      }
    }
  }
  await walk(resolve(dir), '');
  return found.sort((a, b) => (a.path < b.path ? -1 : 1));
}

/** One byte-exact spelling per manifest, so its digest is reproducible. */
function canonical(files) {
  return `${JSON.stringify({ files, v: 1 }, null, 2)}\n`;
}

async function generate(dir, out) {
  const files = await listFiles(dir, out);
  if (files.length === 0) {
    throw new InputError(`${dir} contains no files`);
  }
  const bytes = canonical(files);
  await writeFile(out, bytes);
  process.stdout.write(`${out}: ${files.length} files, sha256 ${sha256Hex(Buffer.from(bytes))}\n`);
}

function differences(listed, onDisk) {
  const disk = new Map(onDisk.map((file) => [file.path, file]));
  const problems = [];
  for (const file of listed) {
    const actual = disk.get(file.path);
    if (actual === undefined) problems.push(`${file.path}: listed but absent from disk`);
    else if (actual.sha256 !== file.sha256) {
      problems.push(`${file.path}: sha256 is ${actual.sha256}, manifest says ${file.sha256}`);
    }
    disk.delete(file.path);
  }
  for (const path of disk.keys()) {
    problems.push(`${path}: on disk but not listed`);
  }
  return problems;
}

async function verify(dir, manifestPath) {
  const raw = await readFile(manifestPath, 'utf8').catch((error) => {
    throw new InputError(`cannot read ${manifestPath}: ${error.message}`);
  });
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new InputError(`${manifestPath} is not valid JSON: ${error.message}`);
  }
  const files = parsed?.files;
  const wellFormed =
    parsed?.v === 1 &&
    Array.isArray(files) &&
    files.every((file) => typeof file?.path === 'string' && typeof file?.sha256 === 'string' && /^[0-9a-f]{64}$/.test(file.sha256));
  if (!wellFormed) {
    throw new InputError(`${manifestPath} is not a canonical version 1 weights manifest`);
  }
  const ordered = files.every((file, i) => i === 0 || files[i - 1].path < file.path);
  const problems = ordered ? [] : [`${manifestPath}: entries are not sorted by path`];
  if (canonical(files) !== raw) {
    problems.push(`${manifestPath}: bytes differ from the canonical spelling, so wts would not match a regeneration`);
  }
  problems.push(...differences(files, await listFiles(dir, manifestPath)));
  if (problems.length > 0) {
    for (const problem of problems) process.stderr.write(`weights.mjs: ${problem}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`${manifestPath}: ${files.length} files match ${dir}\n`);
}

const [mode, first, second] = process.argv.slice(2);
try {
  if (mode === undefined || mode === '--help' || mode === '-h') {
    process.stdout.write(`${USAGE}\n`);
  } else if ((mode === 'generate' || mode === 'verify') && first !== undefined && second !== undefined) {
    if (mode === 'generate') await generate(first, second);
    else await verify(first, second);
  } else {
    throw new InputError(`expected 'generate <weights-dir> <manifest-out>' or 'verify <weights-dir> <manifest>'`);
  }
} catch (error) {
  if (error instanceof InputError) {
    process.stderr.write(`weights.mjs: ${error.message}\nTry 'weights.mjs --help' for usage.\n`);
    process.exitCode = 2;
  } else {
    throw error;
  }
}
