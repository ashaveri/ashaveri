export type EventLogVersion = 1 | 2;

export const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

export interface RuntimeEvent {
  readonly event: string;
  readonly payload: Uint8Array;
  readonly version: EventLogVersion;
}

export interface TdxEvent {
  readonly imr: number;
  readonly eventType: number;
  readonly digest: Uint8Array;
  readonly event: string;
  readonly eventPayload: Uint8Array;
  readonly version: EventLogVersion;
  readonly preimage: string | null;
}

export type PlatformEvidence =
  | { readonly kind: 'tdx'; readonly quote: Uint8Array; readonly eventLog: TdxEvent[] }
  | {
      readonly kind: 'gcp-tdx';
      readonly quote: Uint8Array;
      readonly eventLog: TdxEvent[];
      readonly tpmQuote: unknown;
    }
  | { readonly kind: 'nitro-enclave'; readonly nsmQuote: Uint8Array }
  | { readonly kind: 'aws-nitro-tpm'; readonly attestationDoc: Uint8Array }
  | {
      readonly kind: 'sev-snp';
      readonly report: Uint8Array;
      readonly certChain: Uint8Array[];
      readonly mrConfig: string;
    };

export type StackEvidence = {
  readonly reportData: Uint8Array;
  readonly runtimeEvents: RuntimeEvent[];
  readonly config: string;
  readonly reportDataPayload: string | null;
  readonly stackKind: 'dstack' | 'dstack-pod';
};

export interface Attestation {
  readonly version: 0 | 1;
  readonly platform: PlatformEvidence;
  readonly stack: StackEvidence;
}

export interface TcbVersion {
  readonly blSPL: number;
  readonly teeSPL: number;
  readonly spl4: number;
  readonly spl5: number;
  readonly spl6: number;
  readonly spl7: number;
  readonly snpSPL: number;
  readonly ucodeSPL: number;
}

export function tcbFromU64(value: bigint): TcbVersion {
  return {
    blSPL: Number(value & 0xffn),
    teeSPL: Number((value >> 8n) & 0xffn),
    spl4: Number((value >> 16n) & 0xffn),
    spl5: Number((value >> 24n) & 0xffn),
    spl6: Number((value >> 32n) & 0xffn),
    spl7: Number((value >> 40n) & 0xffn),
    snpSPL: Number((value >> 48n) & 0xffn),
    ucodeSPL: Number((value >> 56n) & 0xffn),
  };
}

export interface SnpPolicy {
  readonly raw: bigint;
  readonly smt: boolean;
  readonly migrateMA: boolean;
  readonly debug: boolean;
  readonly singleSocket: boolean;
}

export interface SnpReport {
  readonly raw: Uint8Array;
  readonly version: number;
  readonly guestSvn: number;
  readonly policy: SnpPolicy;
  readonly familyId: Uint8Array;
  readonly imageId: Uint8Array;
  readonly vmpl: number;
  readonly signatureAlgo: number;
  readonly currentTcb: TcbVersion;
  readonly platformInfo: bigint;
  readonly signerInfo: { signingKey: number; maskChipKey: boolean; authorKeyEn: boolean };
  readonly reportData: Uint8Array;
  readonly measurement: Uint8Array;
  readonly hostData: Uint8Array;
  readonly idKeyDigest: Uint8Array;
  readonly authorKeyDigest: Uint8Array;
  readonly reportId: Uint8Array;
  readonly reportIdMa: Uint8Array;
  readonly reportedTcb: TcbVersion;
  readonly chipId: Uint8Array;
  readonly committedTcb: TcbVersion;
  readonly launchTcb: number;
  readonly cpuidFamily: number;
  readonly cpuidModel: number;
  readonly cpuidStepping: number | null;
  readonly productLine: string | null;
  readonly signature: { readonly r: Uint8Array; readonly s: Uint8Array };
}

export interface TdxQuote {
  readonly raw: Uint8Array;
  /** Quote format version, currently 4 for the TD quotes dStack emits. */
  readonly version: number;
  /** Which key signed the quote; 2 is the PCK-based ECDSA-256 layout handled here. */
  readonly attestationKeyType: number;
  readonly teeType: number;
  readonly mrTd: Uint8Array;
  readonly mrConfigId: Uint8Array;
  readonly mrOwner: Uint8Array;
  readonly mrOwnerConfig: Uint8Array;
  readonly rtmr: readonly [Uint8Array, Uint8Array, Uint8Array, Uint8Array];
  readonly reportData: Uint8Array;
}
