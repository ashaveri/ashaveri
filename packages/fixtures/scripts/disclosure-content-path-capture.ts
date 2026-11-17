/**
 * The real content path: one marked completion put through the copying, rendering and export steps of the
 * applications a deployment's customers use, and nothing of this repository's.
 *
 * The harness in `disclosure-record-vectors.ts` can only measure what it implements itself, which is a
 * reshuffling of the fixture's own bytes. That is enough for a port grading its reader and is not enough
 * for a claim about detectability, so this file hands the served bytes to real applications and records
 * what each produced. The observation it writes is the input the vectors are built from, and the vectors
 * state an outcome only for a stage whose produced bytes they publish: an outcome beside no bytes is not
 * representable there, so a run that could not reach an application leaves the stage recorded instead of
 * estimated.
 *
 * Which application ran which step, and its version, is recorded with the step, because what a rendering
 * does is a fact about that renderer. Where an install sits on a machine is recorded nowhere: the chain is
 * re-runnable by naming each application's binary in the environment this file reads, and a published
 * artifact carrying one machine's directories would be a record of a laptop rather than of a path.
 */
import { execFile, execFileSync, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { delimiter, dirname, join } from 'node:path';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { toBase64Url } from '@ashaveri/receipt';
import { markedBuffered } from './marking-shapes.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const runFile = promisify(execFile);
const OBSERVATION = join(HERE, 'disclosure-content-path-observation.json');

/** The day the run below was made, which is the day each application's version is true of. */
const MEASURED_ON = '2026-11-17';

const ENV_NAMES = {
  chrome: 'ASHAVERI_CHROME',
  curl: 'ASHAVERI_CURL',
  pdftotext: 'ASHAVERI_PDFTOTEXT',
  gs: 'ASHAVERI_GS',
  tesseract: 'ASHAVERI_TESSERACT',
  ffmpeg: 'ASHAVERI_FFMPEG',
} as const;

type ApplicationKey = keyof typeof ENV_NAMES;

interface Application {
  readonly key: ApplicationKey;
  readonly label: string;
  readonly names: readonly string[];
  /** A step of the measured chain, rather than one of the steps named and left. */
  readonly required: boolean;
  /** The flag the application states its own version with, which is not one spelling across them. */
  readonly versionFlag: string;
}

const APPLICATIONS: Record<ApplicationKey, Application> = {
  chrome: { key: 'chrome', label: 'Google Chrome', names: ['chrome', 'google-chrome', 'chrome.exe'], required: true, versionFlag: '--version' },
  curl: { key: 'curl', label: 'curl', names: ['curl', 'curl.exe'], required: true, versionFlag: '--version' },
  pdftotext: { key: 'pdftotext', label: 'poppler pdftotext', names: ['pdftotext', 'pdftotext.exe'], required: true, versionFlag: '-v' },
  gs: { key: 'gs', label: 'Artifex Ghostscript', names: ['gs', 'gswin64c', 'gswin64c.exe'], required: true, versionFlag: '--version' },
  tesseract: { key: 'tesseract', label: 'Tesseract OCR', names: ['tesseract', 'tesseract.exe'], required: true, versionFlag: '--version' },
  ffmpeg: { key: 'ffmpeg', label: 'FFmpeg', names: ['ffmpeg', 'ffmpeg.exe'], required: false, versionFlag: '-version' },
};

/** The binary an application runs as: named in the environment, else the first hit on the PATH. */
function locate(application: Application): string | null {
  const named = process.env[ENV_NAMES[application.key]];
  if (named !== undefined && named !== '') return existsSync(named) ? named : null;
  for (const directory of (process.env.PATH ?? '').split(delimiter).filter((one) => one !== '')) {
    for (const name of application.names) {
      const candidate = join(directory, name);
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
}

/**
 * The version an application states about itself, read out of what it answers its version flag with. The
 * answer is taken whatever the exit status is, because one of these applications prints its banner and
 * exits nonzero by its own convention, and the banner is the thing being recorded.
 */
function versionOf(binary: string, label: string, flag: string): string {
  const answered = spawnSync(binary, [flag], { encoding: 'utf8', timeout: 30_000 });
  const printed = `${answered.stdout ?? ''}${answered.stderr ?? ''}`;
  const line = printed.split('\n').find((one) => /[0-9]/u.test(one)) ?? '';
  assertNamesNoMachine(line, `${label} version`);
  const version = /[0-9][0-9A-Za-z._+-]*/u.exec(line);
  if (version === null) throw new Error(`${label} answered ${flag} with no readable version: ${line}`);
  return version[0];
}

/** A stage's bytes or its recorded reason may not carry one machine's directories, so they are checked. */
function assertNamesNoMachine(text: string, where: string): void {
  if (text.includes(tmpdir())) {
    throw new Error(`${where} carries the directory this run wrote into, which is a fact about one machine`);
  }
  if (/(?:[A-Za-z]:)?[\\/](?:Users|home)[\\/][A-Za-z0-9._-]+/iu.test(text)) {
    throw new Error(`${where} carries a path naming one machine`);
  }
}

interface Stage {
  readonly name: string;
  readonly application: string;
  readonly applicationVersion: string;
  readonly note: string;
  readonly output?: Uint8Array;
}

function measured(name: string, application: Application, version: string, note: string, output: Uint8Array): Stage {
  return { name, application: application.label, applicationVersion: version, note, output };
}

/** A stage the path names and this run did not reach: no bytes, and so nothing for the vectors to state. */
function notRun(name: string, label: string, note: string): Stage {
  return { name, application: label, applicationVersion: '', note };
}

/** The copying step: this package serving the completion over a loopback socket, and a real client writing it down. */
async function throughFetch(curl: string, directory: string, served: Uint8Array): Promise<Uint8Array> {
  const server = createServer((request, response) => {
    if (request.url !== '/transcript') {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json', 'content-length': String(served.length) });
    response.end(served);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const opened = server.address();
  if (opened === null || typeof opened === 'string') {
    throw new Error('the loopback socket the copying step is measured over never opened');
  }
  const written = join(directory, 'fetched.json');
  try {
    // The client runs while this process serves it, so the wait is asynchronous: a synchronous spawn
    // would block the loop the socket is answered from and time out on its own server.
    await runFile(curl, ['-s', '-S', '--fail', '-o', written, `http://127.0.0.1:${String(opened.port)}/transcript`], {
      timeout: 30_000,
    });
    const bytes = new Uint8Array(readFileSync(written));
    if (bytes.length !== served.length) {
      throw new Error(`the client wrote ${String(bytes.length)} bytes where the server offered ${String(served.length)}`);
    }
    if (!bytes.every((one, at) => one === served[at])) {
      throw new Error('the client wrote a file that is not the body the server offered');
    }
    return bytes;
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

/** The browser's flags for a one-shot render of a file, with its own profile directory beside the run. */
function chromeArguments(directory: string, url: string, extra: readonly string[]): string[] {
  return [
    '--headless=new',
    '--disable-gpu',
    '--no-sandbox',
    '--no-first-run',
    `--user-data-dir=${join(directory, 'profile')}`,
    ...extra,
    url,
  ];
}

function throughChromeDom(chrome: string, directory: string, transcript: string): Uint8Array {
  const rendered = execFileSync(
    chrome,
    chromeArguments(directory, pathToFileURL(transcript).href, ['--virtual-time-budget=2000', '--dump-dom']),
    { encoding: 'buffer', timeout: 120_000, maxBuffer: 16_777_216 },
  );
  return new Uint8Array(rendered);
}

function throughChromePdf(chrome: string, directory: string, transcript: string, archive: string): Uint8Array {
  execFileSync(
    chrome,
    chromeArguments(directory, pathToFileURL(transcript).href, [
      '--virtual-time-budget=3000',
      '--no-pdf-header-footer',
      `--print-to-pdf=${archive}`,
    ]),
    { timeout: 120_000, stdio: ['ignore', 'ignore', 'pipe'], maxBuffer: 16_777_216 },
  );
  const bytes = new Uint8Array(readFileSync(archive));
  if (bytes.length === 0) throw new Error('the browser exported an archive of no bytes');
  return bytes;
}

function throughPoppler(binary: string, directory: string, archive: string): Uint8Array {
  const text = join(directory, 'text-one.txt');
  execFileSync(binary, [archive, text], { timeout: 60_000 });
  return new Uint8Array(readFileSync(text));
}

function throughTextwrite(gs: string, directory: string, archive: string): Uint8Array {
  const text = join(directory, 'text-two.txt');
  execFileSync(gs, ['-q', '-dBATCH', '-dNOPAUSE', '-sDEVICE=txtwrite', `-o${text}`, archive], { timeout: 60_000 });
  return new Uint8Array(readFileSync(text));
}

function throughOcr(gs: string, tesseract: string, directory: string, archive: string): Uint8Array {
  const page = join(directory, 'page.png');
  execFileSync(gs, ['-q', '-dBATCH', '-dNOPAUSE', '-sDEVICE=png16m', '-r150', `-o${page}`, archive], { timeout: 120_000 });
  const base = join(directory, 'scanned');
  execFileSync(tesseract, [page, base], { timeout: 120_000 });
  return new Uint8Array(readFileSync(`${base}.txt`));
}

/**
 * The line an application answered a refused call with: the error stream is a string or a buffer
 * depending on how the call was asked to encode it, and it is the answer that says what was unsupported.
 * The address of the context that spoke is stripped, because it belongs to the run and not to the answer.
 */
function answeredLine(err: unknown): string | undefined {
  const stream = typeof err === 'object' && err !== null && 'stderr' in err ? (err as { stderr: unknown }).stderr : undefined;
  const text = typeof stream === 'string' ? stream : stream instanceof Uint8Array ? new TextDecoder().decode(stream) : '';
  return text
    .split('\n')
    .map((line) => line.replace(/@\s*0[0-9a-f]{7,16}/giu, '').trim())
    .find((line) => line !== '');
}

/**
 * The media step, which is the step a JSON transcript has no reading for. The attempt is made against a
 * container the application does write, so the branch that produces bytes is the branch that measured them.
 */
function throughMediaAttempt(ffmpeg: string, version: string, directory: string, served: Uint8Array): Stage {
  const name = 'media-container-transcode';
  const application = APPLICATIONS.ffmpeg;
  writeFileSync(join(directory, 'transcript-for-media.json'), served);
  const container = join(directory, 'transcript.mkv');
  try {
    execFileSync(
      ffmpeg,
      ['-v', 'error', '-y', '-i', 'transcript-for-media.json', '-c', 'copy', container],
      { cwd: directory, timeout: 60_000, stdio: ['ignore', 'ignore', 'pipe'], maxBuffer: 4_194_304 },
    );
    const bytes = new Uint8Array(readFileSync(container));
    if (bytes.length === 0) throw new Error('the remux wrote a container of no bytes');
    return measured(name, application, version, 'The transcript remuxed into a media container, which is the step the mark was never a part of and which these bytes state.', bytes);
  } catch (err) {
    const answer = answeredLine(err);
    if (answer === undefined) throw err;
    assertNamesNoMachine(answer, name);
    return notRun(
      name,
      application.label,
      `Named as a step of this path and not run: ${application.label} ${version} reads no media stream out of these bytes and answered "${answer}", so no transcoded bytes exist and no outcome is stated for the step.`,
    );
  }
}

async function runPath(): Promise<{ readonly served: Uint8Array; readonly stages: readonly Stage[] }> {
  const served = new TextEncoder().encode(markedBuffered().response);
  const directory = mkdtempSync(join(tmpdir(), 'ashaveri-content-path-'));
  try {
    const binaries = new Map<ApplicationKey, string>();
    const versions = new Map<ApplicationKey, string>();
    for (const application of Object.values(APPLICATIONS)) {
      const binary = locate(application);
      if (binary === null) {
        if (application.required) {
          throw new Error(
            `${application.label} runs one of the steps this path is, and no binary for it was found. ` +
              `Name it in ${ENV_NAMES[application.key]} and run this file again: the observation is not written over its absence.`,
          );
        }
        continue;
      }
      binaries.set(application.key, binary);
      versions.set(application.key, versionOf(binary, application.label, application.versionFlag));
    }

    const transcript = join(directory, 'transcript.json');
    writeFileSync(transcript, served);
    const chrome = binaries.get('chrome')!;
    const gs = binaries.get('gs')!;
    const archivePath = join(directory, 'archive.pdf');
    const archiveBytes = throughChromePdf(chrome, directory, transcript, archivePath);

    const stages: Stage[] = [
      measured(
        'client-fetch-to-file',
        APPLICATIONS.curl,
        versions.get('curl')!,
        'The served body written to a file by a real client over a loopback socket: the copying step, which moves the bytes and changes none of them.',
        await throughFetch(binaries.get('curl')!, directory, served),
      ),
      measured(
        'browser-rendered-document',
        APPLICATIONS.chrome,
        versions.get('chrome')!,
        'The same file opened in the browser and serialized as the document it renders, so the region has to survive markup wrapped around it.',
        throughChromeDom(chrome, directory, transcript),
      ),
      measured(
        'browser-exported-pdf',
        APPLICATIONS.chrome,
        versions.get('chrome')!,
        'That rendered page exported to PDF by the browser with its page header and footer off, which is the archive a customer keeps.',
        archiveBytes,
      ),
      measured(
        'pdf-text-export',
        APPLICATIONS.pdftotext,
        versions.get('pdftotext')!,
        'The text one extractor takes back out of that archive, which is what a reader holds when they copy the page out of the PDF.',
        throughPoppler(binaries.get('pdftotext')!, directory, archivePath),
      ),
      measured(
        'pdf-text-export-second-application',
        APPLICATIONS.gs,
        versions.get('gs')!,
        'The same archive read by a second application, so the answer above is not one extractor spacing the page differently.',
        throughTextwrite(gs, directory, archivePath),
      ),
      measured(
        'pdf-page-raster-ocr-text',
        APPLICATIONS.tesseract,
        versions.get('tesseract')!,
        `The page rasterized by ${APPLICATIONS.gs.label} at 150 dots per inch and read by an optical engine, which is the text a scan of the printed page turns into.`,
        throughOcr(gs, binaries.get('tesseract')!, directory, archivePath),
      ),
      notRun(
        'office-document-export',
        'LibreOffice',
        'Named as a step of this path and not run: no office suite was installed where the path was measured, so nothing is stated about what one does to the region.',
      ),
    ];

    const media = binaries.get('ffmpeg');
    if (media === undefined) {
      stages.push(
        notRun(
          'media-container-transcode',
          APPLICATIONS.ffmpeg.label,
          'Named as a step of this path and not run: no FFmpeg binary was found, so no attempt exists to record.',
        ),
      );
    } else {
      stages.push(throughMediaAttempt(media, versions.get('ffmpeg')!, directory, served));
    }

    for (const one of stages) {
      if (one.output !== undefined) assertNamesNoMachine(new TextDecoder('latin1').decode(one.output), one.name);
      assertNamesNoMachine(one.note, `${one.name} note`);
    }
    return { served, stages };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

async function main(): Promise<void> {
  const { served, stages } = await runPath();
  const document = {
    measured: MEASURED_ON,
    start: 'marking-v1.json#buffered-member',
    startBase64Url: toBase64Url(served),
    note:
      'The recorded run of one real content path: the served completion of the marking suite fetched by a client, rendered and exported by a browser, read back out of the archive by two text extractors and by an optical engine, and attempted through a media remux. Each stage names the application and the version that produced its bytes, and a stage with no bytes is one that did not run, for which the vectors built from this file state no outcome. Where an install sits on a machine is not stated here.',
    stages: stages.map((one) => ({
      name: one.name,
      application: one.application,
      applicationVersion: one.applicationVersion,
      note: one.note,
      ...(one.output === undefined ? {} : { outputBase64Url: toBase64Url(one.output) }),
    })),
  };
  writeFileSync(OBSERVATION, `${JSON.stringify(document, null, 2)}\n`);
  for (const one of document.stages) {
    const bytes = one.outputBase64Url === undefined ? 'no bytes' : `${String(one.outputBase64Url.length)} base64url`;
    console.log(`${one.name}: ${one.application} ${one.applicationVersion} ${bytes}`);
  }
}

await main();
