import { collateralRefusal, quoteOrDigest, type CollateralRefusal } from './errors.js';
import { utf8 } from './bytes.js';
import type { OriginDeclaration } from './intel-origin.js';
import type { CollateralTransport } from './types.js';

/** The bytes an answer arrived with, the issuer chain that arrived beside them, and the instant they were seen. */
export interface FetchedCollateral {
  readonly bytes: Uint8Array;
  /**
   * The issuer chain header exactly as it arrived, or null where the declaration names no header or the answer
   * carried none. Nothing here decodes the spelling the origin used, splits one certificate from the next or
   * reorders them: a signature is weighed against the bytes that came beside it, and a copy this path had
   * rewritten is no longer those bytes. A reader that wants the text inside decodes it where it decides to.
   *
   * An absent header answers with no chain rather than with a refusal: the body is the document the origin
   * answered with, and this path reads no less of it because one header was left out.
   */
  readonly chain: Uint8Array | null;
  /**
   * Unix seconds at the instant the last byte landed, on the clock this run was given. It is the only
   * thing that separates an answer from an archive, which is why it travels beside the bytes.
   */
  readonly observedAt: number;
}

export type FetchOutcome = { readonly fetched: FetchedCollateral } | { readonly refusal: CollateralRefusal };

export interface FetchContext {
  readonly transport?: CollateralTransport;
  /** Wall clock in seconds since the epoch. Injectable because the refusals are tested without a network. */
  readonly clock?: () => number;
}

/**
 * One request to the declared host, under the declared timeout.
 *
 * Three rules hold the path to a single origin. The address is checked against the declaration before
 * anything is asked of it, so a hand-built URL cannot borrow this code's credentials-free position.
 * A redirect is refused rather than followed, because the answer to "who signed this" is only useful
 * while it names one host. And nothing is sent that identifies the caller: no authorization header, no
 * cookie, no key, since a feed that wants one is holding secret material and belongs to a secret
 * manager rather than to a source dependency.
 */
export async function fetchFromOrigin(
  url: string,
  declaration: OriginDeclaration,
  context: FetchContext = {},
): Promise<FetchOutcome> {
  const transport = context.transport ?? globalThis.fetch;
  const asked = askedOf(url, declaration);
  if (asked !== null) {
    return { refusal: asked };
  }
  let response: Response;
  try {
    response = await transport(url, {
      method: 'GET',
      redirect: 'error',
      signal: AbortSignal.timeout(declaration.timeoutMs),
      headers: { accept: declaration.signature.mediaType },
    });
  } catch (err) {
    const name = err instanceof Error ? err.name : 'unknown';
    const why = err instanceof Error ? err.message : '';
    return {
      refusal: collateralRefusal(declaration.refusals.transport, `${url} answered nothing under a ${declaration.timeoutMs}ms wait (${name}: ${quoteOrDigest(why)})`),
    };
  }
  if (!response.ok) {
    return {
      refusal: collateralRefusal(declaration.refusals.status, `${url} answered ${String(response.status)}`),
    };
  }
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > declaration.maxResponseBytes) {
    return {
      refusal: collateralRefusal(declaration.refusals.oversize, `${url} announced ${String(declared)} bytes, over the ${String(declaration.maxResponseBytes)} the path declares`),
    };
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > declaration.maxResponseBytes) {
    return {
      refusal: collateralRefusal(declaration.refusals.oversize, `${url} sent ${String(bytes.byteLength)} bytes, over the ${String(declaration.maxResponseBytes)} the path declares`),
    };
  }
  if (bytes.byteLength === 0) {
    return { refusal: collateralRefusal(declaration.refusals.envelope, `${url} answered with an empty body`) };
  }
  const named = declaration.chainHeader === null ? null : response.headers.get(declaration.chainHeader);
  const chain = named === null || named.length === 0 ? null : utf8(named);
  return { fetched: { bytes, chain, observedAt: (context.clock ?? wallClock)() } };
}

/** Unix seconds, which is the unit every instant in this package is stated in. */
export function wallClock(): number {
  return Math.floor(Date.now() / 1000);
}

function askedOf(url: string, declaration: OriginDeclaration): CollateralRefusal | null {
  let target: URL;
  try {
    target = new URL(url);
  } catch {
    return collateralRefusal(declaration.refusals.envelope, `${quoteOrDigest(url)} is not an address`);
  }
  if (target.protocol !== 'https:' || target.host !== declaration.host) {
    return collateralRefusal(
      declaration.refusals.envelope,
      `${declaration.name} is read from https://${declaration.host} alone and the address names ${quoteOrDigest(target.host)}`,
    );
  }
  return null;
}
