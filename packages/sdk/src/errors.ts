export type SdkErrorCode =
  | 'NO_POLICY'
  | 'BAD_MANIFEST'
  | 'MANIFEST_KEY_NOT_PINNED'
  // A deployment manifest that arrives sealed, and the two ways a seal fails to say what a caller
  // needs it to say. The first is the absence of an authentication, the second the presence of one that
  // does not hold: a body altered after the deployment signed it, or a key that is not the one named in
  // the header. Neither is `BAD_MANIFEST`, which is a document that does not parse, and neither is
  // `MANIFEST_KEY_NOT_PINNED`, which is about the keys a manifest lists for signing receipts rather
  // than the key that signed the manifest itself.
  | 'MANIFEST_NOT_AUTHENTICATED'
  | 'MANIFEST_SIGNATURE_INVALID'
  // A receipt's own claim about which key epoch signed it, checked against what the deployment
  // publishes about its rotation. Two refusals where one would blur who disagreed: a manifest that
  // never named this epoch, and a manifest that named it and says this is not its key or not its
  // window. A third question, whether this client designated the key at all, stays
  // `MANIFEST_KEY_NOT_PINNED`'s alone.
  | 'MANIFEST_EPOCH_UNDECLARED'
  | 'MANIFEST_EPOCH_DISAGREES'
  | 'RECEIPT_NOT_FOUND'
  | 'REQUEST_HASH_MISMATCH'
  | 'RESPONSE_HASH_MISMATCH'
  | 'ISSUER_NOT_ALLOWED'
  | 'INSTANCE_NOT_ALLOWED'
  | 'MEASUREMENT_NOT_ALLOWED'
  | 'GATEWAY_ERROR'
  | 'NOT_RECEIPTED'
  // A capture record. Both answer the question of what a reader was told to read and did not
  // get, and both sit beside NOT_RECEIPTED for that reason. Neither is it, because a capture
  // record is not a receipt, and the second is a contradiction between a claim and the bytes
  // beside it rather than a shape problem a re-encode could fix. A comment inside a declared
  // union carries no semicolon, because the document contract reads a union to its first one.
  | 'NOT_CAPTURE_RECORD'
  | 'CAPTURE_SIGNATURE_NOT_CARRIED'
  // Strict mode only: the hardware evidence behind a receipt. Listed in the order
  // the checks run, so the code identifies the stage that rejected the document.
  | 'EVIDENCE_NOT_FOUND'
  | 'EVIDENCE_NOT_HARDWARE'
  | 'EVIDENCE_NO_TRUST_ANCHORS'
  | 'EVIDENCE_DIGEST_MISMATCH'
  | 'EVIDENCE_VERIFICATION_FAILED'
  | 'EVIDENCE_NOT_VERIFIED'
  | 'EVIDENCE_REPORT_DATA_MISMATCH'
  | 'EVIDENCE_TEE_MISMATCH'
  | 'EVIDENCE_GPU_MISSING'
  | 'EVIDENCE_MEASUREMENT_MISMATCH'
  // A credential the client cannot use, refused before anything went on the wire.
  | 'AUTH_CONFIG'
  // A verification policy read out of a file. The format is a trust anchor, so every one of these
  // is a refusal to publish a digest over a document the loader is not certain it read correctly.
  | 'POLICY_FILE_INVALID'
  | 'POLICY_FILE_UNREADABLE'
  | 'POLICY_NOTHING_PINNED'
  | 'POLICY_EMPTY_PIN'
  | 'POLICY_ANCHOR_UNREADABLE'
  | 'POLICY_ANCHOR_DIGEST_MISMATCH';

export class SdkError extends Error {
  readonly code: SdkErrorCode;

  constructor(code: SdkErrorCode, message: string) {
    super(message);
    this.name = 'SdkError';
    this.code = code;
  }
}

export function sdkError(code: SdkErrorCode, message: string): never {
  throw new SdkError(code, message);
}
