import { fail } from './errors.js';
import { isMsgpackMapPrefix, MsgpackReader } from './msgpack.js';
import { ScaleReader } from './scale.js';
import type { Attestation, EventLogVersion, PlatformEvidence, StackEvidence, TdxEvent } from './types.js';

export function decodeAttestation(bytes: Uint8Array): Attestation {
  if (bytes.length === 0) {
    fail('MALFORMED_ATTESTATION', 'attestation bytes are empty');
  }
  const first = bytes[0] as number;
  if (first === 0x00) {
    return decodeV0(new ScaleReader(bytes));
  }
  if (isMsgpackMapPrefix(first)) {
    return decodeV1(new MsgpackReader(bytes));
  }
  fail('MALFORMED_ATTESTATION', `unknown attestation wire format (first byte 0x${first.toString(16).padStart(2, '0')})`);
}

function decodeV0(reader: ScaleReader): Attestation {
  const tag = reader.readByte('version tag');
  if (tag !== 0x00) {
    fail('UNSUPPORTED_VERSION', `legacy SCALE envelope tag ${tag}`);
  }
  const platform = decodeV0Platform(reader);
  const runtimeEvents = reader.readVecItems(
    (ctx) => {
      const event = reader.readString(`${ctx}.event`);
      const payload = reader.readVec(`${ctx}.payload`);
      return { event, payload, version: 1 as EventLogVersion };
    },
    'runtime_events',
  );
  const reportData = reader.readFixed(64, 'report_data');
  const config = reader.readString('config');
  reader.assertEnd('V0 attestation');
  const stack: StackEvidence = {
    reportData,
    runtimeEvents,
    config,
    reportDataPayload: null,
    stackKind: 'dstack',
  };
  return { version: 0, platform, stack };
}

function decodeV0Platform(reader: ScaleReader): PlatformEvidence {
  const variant = reader.readByte('platform variant');
  switch (variant) {
    case 0: {
      const quote = reader.readVec('tdx.quote');
      const eventLog = reader.readVecItems((ctx) => decodeV0TdxEvent(reader, ctx), 'tdx.event_log');
      return { kind: 'tdx', quote, eventLog };
    }
    case 1:
      fail('UNSUPPORTED_VERSION', 'gcp-tdx platform evidence is only supported in the V1 msgpack envelope');
    case 2: {
      const nsmQuote = reader.readVec('nitro.nsm_quote');
      return { kind: 'nitro-enclave', nsmQuote };
    }
    case 3: {
      const report = reader.readVec('snp.report');
      const certChain = reader.readVecItems((ctx) => reader.readVec(ctx), 'snp.cert_chain');
      const mrConfig = reader.readString('snp.mr_config');
      return { kind: 'sev-snp', report, certChain, mrConfig };
    }
    case 4: {
      const attestationDoc = reader.readVec('nitro-tpm.attestation_doc');
      return { kind: 'aws-nitro-tpm', attestationDoc };
    }
    default:
      fail('UNKNOWN_PLATFORM', `legacy SCALE variant ${variant}`);
  }
}

function decodeV0TdxEvent(reader: ScaleReader, context: string): TdxEvent {
  const imr = reader.readU32(`${context}.imr`);
  const eventType = reader.readU32(`${context}.event_type`);
  const digest = reader.readVec(`${context}.digest`);
  const event = reader.readString(`${context}.event`);
  const eventPayload = reader.readVec(`${context}.event_payload`);
  return { imr, eventType, digest, event, eventPayload, version: 1, preimage: null };
}

function decodeV1(reader: MsgpackReader): Attestation {
  const count = reader.readMapHeader('attestation');
  let version: number | null = null;
  let platform: PlatformEvidence | null = null;
  let stack: StackEvidence | null = null;
  for (let i = 0; i < count; i++) {
    const key = reader.readStr('attestation key');
    switch (key) {
      case 'version':
        version = reader.readUint('attestation.version');
        break;
      case 'platform':
        platform = decodeV1Platform(reader);
        break;
      case 'stack':
        stack = decodeV1Stack(reader);
        break;
      default:
        reader.skipValue(`attestation.${key}`);
    }
  }
  if (version !== 1) {
    fail('UNSUPPORTED_VERSION', `V1 envelope version field is ${version}`);
  }
  if (platform === null) {
    fail('MALFORMED_ATTESTATION', 'platform evidence is missing');
  }
  if (stack === null) {
    fail('MALFORMED_ATTESTATION', 'stack evidence is missing');
  }
  reader.assertEnd('V1 attestation');
  return { version: 1, platform, stack };
}

function decodeV1Platform(reader: MsgpackReader): PlatformEvidence {
  const count = reader.readMapHeader('platform');
  let kind: string | null = null;
  let data: unknown = null;
  for (let i = 0; i < count; i++) {
    const key = reader.readStr('platform key');
    if (key === 'kind') {
      kind = reader.readStr('platform.kind');
    } else if (key === 'data') {
      data = reader.readValue('platform.data');
    } else {
      reader.skipValue(`platform.${key}`);
    }
  }
  if (kind === null || data === null || typeof data !== 'object') {
    fail('MALFORMED_ATTESTATION', 'platform evidence is missing kind or data');
  }
  const fields = data as Record<string, unknown>;
  switch (kind) {
    case 'tdx':
      return {
        kind: 'tdx',
        quote: requireBin(fields, 'quote', 'platform.tdx'),
        eventLog: readTdxEvents(requireArray(fields, 'event_log', 'platform.tdx'), 'platform.tdx.event_log'),
      };
    case 'gcp-tdx':
      return {
        kind: 'gcp-tdx',
        quote: requireBin(fields, 'quote', 'platform.gcp-tdx'),
        eventLog: readTdxEvents(requireArray(fields, 'event_log', 'platform.gcp-tdx'), 'platform.gcp-tdx.event_log'),
        tpmQuote: fields['tpm_quote'],
      };
    case 'nitro-enclave':
      return { kind: 'nitro-enclave', nsmQuote: requireBin(fields, 'nsm_quote', 'platform.nitro-enclave') };
    case 'aws-nitro-tpm':
      return { kind: 'aws-nitro-tpm', attestationDoc: requireBin(fields, 'attestation_doc', 'platform.aws-nitro-tpm') };
    case 'sev-snp':
      return {
        kind: 'sev-snp',
        report: requireBin(fields, 'report', 'platform.sev-snp'),
        certChain: requireArray(fields, 'cert_chain', 'platform.sev-snp').map((entry, i) => {
          if (!(entry instanceof Uint8Array)) {
            fail('MALFORMED_ATTESTATION', `platform.sev-snp.cert_chain[${i}] is not bin data`);
          }
          return entry;
        }),
        mrConfig: requireStr(fields, 'mr_config', 'platform.sev-snp'),
      };
    default:
      fail('UNKNOWN_PLATFORM', kind);
  }
}

function decodeV1Stack(reader: MsgpackReader): StackEvidence {
  const count = reader.readMapHeader('stack');
  let kind: string | null = null;
  let data: unknown = null;
  for (let i = 0; i < count; i++) {
    const key = reader.readStr('stack key');
    if (key === 'kind') {
      kind = reader.readStr('stack.kind');
    } else if (key === 'data') {
      data = reader.readValue('stack.data');
    } else {
      reader.skipValue(`stack.${key}`);
    }
  }
  if (kind !== 'dstack' && kind !== 'dstack-pod') {
    fail(kind === null ? 'MALFORMED_ATTESTATION' : 'UNKNOWN_STACK', `stack kind is ${kind}`);
  }
  if (data === null || typeof data !== 'object') {
    fail('MALFORMED_ATTESTATION', 'stack evidence is missing data');
  }
  const fields = data as Record<string, unknown>;
  const reportData = requireBin(fields, 'report_data', 'stack');
  if (reportData.length !== 64) {
    fail('MALFORMED_ATTESTATION', `stack.report_data must be 64 bytes, got ${reportData.length}`);
  }
  const runtimeEvents = requireArray(fields, 'runtime_events', 'stack').map((entry, i) => {
    if (entry === null || typeof entry !== 'object' || entry instanceof Uint8Array) {
      fail('MALFORMED_ATTESTATION', `stack.runtime_events[${i}] is not a map`);
    }
    const eventFields = entry as Record<string, unknown>;
    const event = requireStr(eventFields, 'event', `stack.runtime_events[${i}]`);
    const payloadValue = eventFields['payload'];
    if (!(payloadValue instanceof Uint8Array)) {
      fail('MALFORMED_ATTESTATION', `stack.runtime_events[${i}].payload is not bin data`);
    }
    const version = eventFields['version'];
    if (version === undefined || version === null) {
      return { event, payload: payloadValue, version: 1 as EventLogVersion };
    }
    if (version !== 1 && version !== 2) {
      fail('MALFORMED_ATTESTATION', `stack.runtime_events[${i}].version must be 1 or 2, got ${String(version)}`);
    }
    return { event, payload: payloadValue, version: version as EventLogVersion };
  });
  const config = requireStr(fields, 'config', 'stack');
  const reportDataPayloadValue = fields['report_data_payload'];
  const reportDataPayload =
    kind === 'dstack-pod'
      ? requireStr(fields, 'report_data_payload', 'stack')
      : typeof reportDataPayloadValue === 'string'
        ? reportDataPayloadValue
        : null;
  return { reportData, runtimeEvents, config, reportDataPayload, stackKind: kind };
}

function readTdxEvents(entries: unknown[], context: string): TdxEvent[] {
  return entries.map((entry, i) => {
    if (entry === null || typeof entry !== 'object' || entry instanceof Uint8Array) {
      fail('MALFORMED_ATTESTATION', `${context}[${i}] is not a map`);
    }
    const fields = entry as Record<string, unknown>;
    const imr = requireUint(fields, 'imr', `${context}[${i}]`);
    const eventType = requireUint(fields, 'event_type', `${context}[${i}]`);
    const digest = requireBin(fields, 'digest', `${context}[${i}]`);
    const event = requireStr(fields, 'event', `${context}[${i}]`);
    const eventPayload = requireBin(fields, 'event_payload', `${context}[${i}]`);
    const versionValue = fields['version'];
    let version: EventLogVersion = 1;
    if (versionValue !== undefined && versionValue !== null) {
      if (versionValue !== 1 && versionValue !== 2) {
        fail('MALFORMED_ATTESTATION', `${context}[${i}].version must be 1 or 2, got ${String(versionValue)}`);
      }
      version = versionValue;
    }
    const preimageValue = fields['preimage'];
    const preimage =
      preimageValue === undefined || preimageValue === null ? null : typeof preimageValue === 'string' ? preimageValue : null;
    if (preimageValue !== undefined && preimageValue !== null && typeof preimageValue !== 'string') {
      fail('MALFORMED_ATTESTATION', `${context}[${i}].preimage is not a string`);
    }
    return { imr, eventType, digest, event, eventPayload, version, preimage };
  });
}

function requireBin(fields: Record<string, unknown>, key: string, context: string): Uint8Array {
  const value = fields[key];
  if (!(value instanceof Uint8Array)) {
    fail('MALFORMED_ATTESTATION', `${context}.${key} is missing or not bin data`);
  }
  return value;
}

function requireStr(fields: Record<string, unknown>, key: string, context: string): string {
  const value = fields[key];
  if (typeof value !== 'string') {
    fail('MALFORMED_ATTESTATION', `${context}.${key} is missing or not a string`);
  }
  return value;
}

function requireUint(fields: Record<string, unknown>, key: string, context: string): number {
  const value = fields[key];
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    fail('MALFORMED_ATTESTATION', `${context}.${key} is missing or not an unsigned integer`);
  }
  return value;
}

function requireArray(fields: Record<string, unknown>, key: string, context: string): unknown[] {
  const value = fields[key];
  if (!Array.isArray(value)) {
    fail('MALFORMED_ATTESTATION', `${context}.${key} is missing or not an array`);
  }
  return value;
}
