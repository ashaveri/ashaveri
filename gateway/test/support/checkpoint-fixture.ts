import { createPrivateKey } from 'node:crypto';
import { hashRequest, issueReceipt, sealDeploymentManifest, signingKeyFromSeed, toBase64Url, toHex, type ReceiptPayloadV1 } from '@ashaveri/receipt';
import { pinPublicKeyOfRaw, type BootCapture, type PinKeyPair } from './checkpoint-pin.js';

// Shared synthetic issuers make self-pin tests exercise actual receipt signatures.
const signingKey = (label: string) => signingKeyFromSeed(hashRequest(Buffer.from(`checkpoint-fixture:${label}`)));
export const fixtureIssuer = signingKey('issuer');
export const fixtureSuccessor = signingKey('successor');
export const fixtureSeal = signingKey('manifest');
export const fixtureManifestKeys = { [toHex(fixtureSeal.kid)]: toBase64Url(fixtureSeal.publicKey) };

export const fixtureIssuerPin: PinKeyPair = {
  keyId: toHex(fixtureIssuer.kid),
  publicKey: pinPublicKeyOfRaw(toBase64Url(fixtureIssuer.publicKey)),
  privateKey: createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), fixtureIssuer.privateKey]),
    format: 'der', type: 'pkcs8',
  }).export({ format: 'pem', type: 'pkcs8' }).toString(),
};

export function fixtureCapture(options: {
  boot?: string;
  later?: boolean;
  unsigned?: boolean;
  windowless?: boolean;
  document?: (value: Record<string, unknown>) => void;
  payload?: Partial<ReceiptPayloadV1>;
} = {}): BootCapture {
  const later = options.later === true;
  const key = later ? fixtureSuccessor : fixtureIssuer;
  const iat = later ? 200 : 100;
  const digest = hashRequest(Buffer.from('checkpoint-fixture'));
  const payload: ReceiptPayloadV1 = {
    v: 1, iss: 'fixture-issuer', ins: 'repeated-instance', epk: later ? 1 : 0, iat,
    nce: new Uint8Array(16), req: digest, res: digest, mdl: 'fixture-model', wts: digest,
    meas: { tee: 'software', m: digest },
    att: { d: digest, ts: iat, url: 'mock://fixture' }, tok: { p: 1, c: 1 },
    mk: { sch: 'none', d: hashRequest(new Uint8Array()) },
    sd: { name: 'fixture clock', uncertaintySeconds: null },
    cva: {
      collateral: { presence: 'not-taken-in', reason: 'synthetic fixture' },
      validity: { presence: 'not-taken-in', reason: 'synthetic fixture' },
    },
    itm: [{ t: iat, d: digest }],
    ...options.payload,
  };
  const keys = (later ? [fixtureIssuer, fixtureSuccessor] : [fixtureIssuer]).map((each, epoch) => ({
    kid: toHex(each.kid), alg: 'Ed25519', publicKey: toBase64Url(each.publicKey),
    ...(options.windowless === true ? {} : { epk: epoch, validFrom: epoch === 0 ? 50 : 150 }),
  }));
  const document: Record<string, unknown> = {
    v: 1, iss: payload.iss, ins: payload.ins, epk: later ? 1 : 0,
    keys, models: [], meas: { tee: 'software', m: toHex(digest) },
  };
  options.document?.(document);
  const json = Buffer.from(JSON.stringify(document));
  return {
    boot: options.boot ?? (later ? 'fixture-boot-2' : 'fixture-boot-1'),
    manifest: options.unsigned === true ? json : sealDeploymentManifest(json, fixtureSeal),
    receipts: [{ id: later ? 'fixture-receipt-2' : 'fixture-receipt-1', bytes: issueReceipt(payload, key) }],
  };
}
