import { describe, expect, it } from 'vitest';
import { sha384 } from '@noble/hashes/sha2.js';
import { toHex, utf8 } from '../src/bytes.js';
import {
  canonicalizeDocument,
  canonicalizeSubtree,
  collectElements,
  readXml,
  type XmlAttribute,
  type XmlDocument,
  type XmlElement,
  type XmlText,
} from '../src/xml.js';

/**
 * Canonical XML version 1.1, held to bytes written out by hand.
 *
 * The expected sequences in the golden cases were derived from the rules before the canonicalizer they check was
 * run, and each was then measured against implementations that are not this repository's code: libxml2's
 * `xmllint --c14n11`, the .NET `XmlDsigC14NTransform`, and the JDK's `http://www.w3.org/2006/12/xml-c14n11`
 * canonicalization read out through the `DigestValue` it writes for a reference naming one element by its `Id`. A
 * writer that shares an assumption with the code it feeds cannot show that assumption wrong, so the bytes here
 * stand on their own and the canonicalizer has to meet them. The SignedInfo sequence carries the weight:
 * `DIGEST_HEX=ec8a8644532ab4182406b80fcfb49261b019e05e048ada464e1e6b80aa64715a` is what the JDK wrote for that
 * element, and the SHA-256 of the bytes below is the same number. The report of 23 October carries the rest of
 * those measurements, including the two places where implementations of this specification disagree.
 *
 * Two cases hold a value no accepted spelling of this reader's subset can carry: a tab, a line feed and a
 * carriage return inside an attribute value, and a carriage return inside text, since a character reference is
 * refused where it is met and a line ending is settled before parsing. Those trees are built by hand so the escape
 * tables stay pinned to bytes rather than dropped as unreachable.
 */

const DS = 'http://www.w3.org/2000/09/xmldsig#';
const ISO = 'http://standards.iso.org/iso/19770/-2/2015/schema.xsd';
const XML_NAMESPACE = 'http://www.w3.org/XML/1998/namespace';

function read(text: string): XmlDocument {
  const answer = readXml(text);
  if ('document' in answer) {
    return answer.document;
  }
  throw new Error(`the reader refused the document of a canonicalization case: ${answer.why}`);
}

function bytesOf(answer: ReturnType<typeof canonicalizeDocument>): Uint8Array {
  if ('bytes' in answer) {
    return answer.bytes;
  }
  throw new Error(`the canonicalizer refused: ${answer.why}`);
}

function whyOf(answer: ReturnType<typeof canonicalizeDocument>): string {
  if ('bytes' in answer) {
    throw new Error(`the canonicalizer handed back bytes where a refusal was asked for`);
  }
  return answer.why;
}

function elementOf(document: XmlDocument, namespace: string, localName: string): XmlElement {
  const found = collectElements(document).filter((one) => one.namespace === namespace && one.localName === localName);
  if (found.length !== 1) {
    throw new Error(`${String(found.length)} elements in ${namespace} named ${localName}`);
  }
  return found[0] as XmlElement;
}

function whole(text: string, comments = false): string {
  return new TextDecoder().decode(bytesOf(canonicalizeDocument(read(text), null, { comments })));
}

function part(text: string, namespace: string, localName: string, comments = false): string {
  return new TextDecoder().decode(bytesOf(canonicalizeSubtree(elementOf(read(text), namespace, localName), { comments })));
}

const GOLDEN_INPUT =
  '<r xmlns="urn:example:root" xmlns:b="urn:example:beta" xmlns:a="urn:example:alpha" b:second="two" plain="1" a:third="3">' +
  '<s xmlns:c="urn:example:gamma" c:five="5" q="say &quot;hi&quot;"><!--gone--><e/><t>less &lt; and &amp; and &gt; and &quot;quote&quot; and &apos;apos&apos;</t></s>' +
  '<u><![CDATA[<y> & z]]></u></r>';

const GOLDEN_CANONICAL =
  '<r xmlns="urn:example:root" xmlns:a="urn:example:alpha" xmlns:b="urn:example:beta" plain="1" a:third="3" b:second="two">' +
  '<s xmlns:c="urn:example:gamma" q="say &quot;hi&quot;" c:five="5">' +
  '<e></e>' +
  '<t>less &lt; and &amp; and &gt; and "quote" and \'apos\'</t>' +
  '</s>' +
  '<u>&lt;y&gt; &amp; z</u>' +
  '</r>';

const GOLDEN_CANONICAL_WITH_COMMENTS = GOLDEN_CANONICAL.replace('c:five="5">', 'c:five="5"><!--gone-->');

const MANIFEST_INPUT =
  `<SoftwareIdentity xmlns="${ISO}" xmlns:ds="${DS}" tagId="sample" version="1">` +
  '<Entity name="Vendor"></Entity>' +
  '<ds:Signature><ds:SignedInfo Id="si">' +
  '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"></ds:CanonicalizationMethod>' +
  '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"></ds:SignatureMethod>' +
  '<ds:Reference URI=""><ds:Transforms>' +
  `<ds:Transform Algorithm="${DS}enveloped-signature"></ds:Transform>` +
  '<ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"></ds:Transform>' +
  '</ds:Transforms>' +
  '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"></ds:DigestMethod>' +
  '<ds:DigestValue>abc+def/ghi=</ds:DigestValue></ds:Reference></ds:SignedInfo>' +
  '<ds:SignatureValue>x=</ds:SignatureValue></ds:Signature></SoftwareIdentity>';

const SIGNED_INFO_CANONICAL =
  `<ds:SignedInfo xmlns="${ISO}" xmlns:ds="${DS}" Id="si">` +
  '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"></ds:CanonicalizationMethod>' +
  '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"></ds:SignatureMethod>' +
  '<ds:Reference URI=""><ds:Transforms>' +
  `<ds:Transform Algorithm="${DS}enveloped-signature"></ds:Transform>` +
  '<ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"></ds:Transform>' +
  '</ds:Transforms>' +
  '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"></ds:DigestMethod>' +
  '<ds:DigestValue>abc+def/ghi=</ds:DigestValue></ds:Reference></ds:SignedInfo>';

const SIGNED_INFO_SHA384 = '58a639846efc5ce3420369c5a5effe8491d55bd78ba76e093a34a7502b870747694029f0094fc05e55d962332389b791';
const SIGNED_INFO_MUTATED_SHA384 = 'd292e0fde2df7123c908e445701d479903e9b037953f85904b9aa40db1904b6dedcd485f185dae6f763fd1b074ed9d3e';

/** The manifest with its own signature left out of the node-set, which is what the enveloped transform is. */
const MANIFEST_WITHOUT_SIGNATURE =
  `<SoftwareIdentity xmlns="${ISO}" xmlns:ds="${DS}" tagId="sample" version="1"><Entity name="Vendor"></Entity></SoftwareIdentity>`;

const BOOK_LANGUAGE = '<book xmlns="urn:example:book" xml:lang="en"><chapter Id="outer"><body Id="inner" xml:lang="fr"><line>text</line></body></chapter></book>';

function handBuiltText(value: string): XmlElement {
  const text: XmlText = { kind: 'text', characters: value };
  return { kind: 'element', name: 'note', prefix: '', localName: 'note', namespace: '', attributes: [], children: [text], inScope: new Map<string, string>(), parent: null };
}

function handBuiltValue(value: string): XmlElement {
  const attribute: XmlAttribute = { prefix: '', localName: 'value', namespace: '', value };
  return { kind: 'element', name: 'row', prefix: '', localName: 'row', namespace: '', attributes: [attribute], children: [], inScope: new Map<string, string>(), parent: null };
}

describe('Canonical XML 1.1', () => {
  describe('the golden bytes', () => {
    it('writes a whole document as the sequence derived by hand', () => {
      const bytes = bytesOf(canonicalizeDocument(read(GOLDEN_INPUT)));
      expect(new TextDecoder().decode(bytes)).toBe(GOLDEN_CANONICAL);
      expect(bytes).toEqual(utf8(GOLDEN_CANONICAL));
      expect(bytes.byteLength).toBe(282);
    });

    it('writes the same document with its comment where the caller asks', () => {
      const bytes = bytesOf(canonicalizeDocument(read(GOLDEN_INPUT), null, { comments: true }));
      expect(new TextDecoder().decode(bytes)).toBe(GOLDEN_CANONICAL_WITH_COMMENTS);
      expect(bytes.byteLength).toBe(293);
    });

    it('writes the SignedInfo subtree as the sequence derived by hand', () => {
      const signedInfo = elementOf(read(MANIFEST_INPUT), DS, 'SignedInfo');
      expect(signedInfo.prefix).toBe('ds');
      const bytes = bytesOf(canonicalizeSubtree(signedInfo));
      expect(new TextDecoder().decode(bytes)).toBe(SIGNED_INFO_CANONICAL);
      expect(bytes.byteLength).toBe(734);
      expect(toHex(sha384(bytes))).toBe(SIGNED_INFO_SHA384);
    });

    it('moves the digest when one space of text moves', () => {
      const mutated = MANIFEST_INPUT.replace('<ds:DigestValue>abc+def/ghi=</ds:DigestValue>', '<ds:DigestValue>abc+def/ghi= </ds:DigestValue>');
      const bytes = bytesOf(canonicalizeSubtree(elementOf(read(mutated), DS, 'SignedInfo')));
      expect(toHex(sha384(bytes))).toBe(SIGNED_INFO_MUTATED_SHA384);
      expect(toHex(sha384(bytes))).not.toBe(SIGNED_INFO_SHA384);
    });

    it('leaves one element out of the document where the caller names it', () => {
      const doc = read(MANIFEST_INPUT);
      const bytes = bytesOf(canonicalizeDocument(doc, elementOf(doc, DS, 'Signature')));
      expect(new TextDecoder().decode(bytes)).toBe(MANIFEST_WITHOUT_SIGNATURE);
      expect(bytes.byteLength).toBe(203);
    });

    it('writes a document and its document element as the same bytes', () => {
      const doc = read(GOLDEN_INPUT);
      expect(whole(GOLDEN_INPUT)).toBe(new TextDecoder().decode(bytesOf(canonicalizeSubtree(doc.root))));
    });
  });

  describe('the order the two axes take', () => {
    it('orders two attributes by the namespace each sits in', () => {
      expect(whole('<r xmlns:a="urn:example:a"><e b="2" a:b="1" z="3"/></r>'))
        .toBe('<r xmlns:a="urn:example:a"><e b="2" z="3" a:b="1"></e></r>');
    });

    it('orders names by character position and not by a locale', () => {
      expect(whole('<e xmlns:a="urn:example:a" a:_2="1" a:_10="2" a:_1="3"/>'))
        .toBe('<e xmlns:a="urn:example:a" a:_1="3" a:_10="2" a:_2="1"></e>');
    });

    it('writes the default declaration first and the bound prefixes after it', () => {
      expect(whole('<r xmlns:z="urn:z" xmlns="urn:example:d" xmlns:a="urn:a"><child/></r>'))
        .toBe('<r xmlns="urn:example:d" xmlns:a="urn:a" xmlns:z="urn:z"><child></child></r>');
      expect(whole('<r xmlns:n9="urn:n9" xmlns:n10="urn:n10" xmlns:_a="urn:ua"><x/></r>'))
        .toBe('<r xmlns:_a="urn:ua" xmlns:n10="urn:n10" xmlns:n9="urn:n9"><x></x></r>');
    });

    it('writes the namespace axis before the attribute axis', () => {
      expect(whole('<r b="1" xmlns:a="urn:example:a" a:x="2"/>'))
        .toBe('<r xmlns:a="urn:example:a" b="1" a:x="2"></r>');
    });

    it('renders a declaration where it first binds and not where it is repeated', () => {
      const text = '<manifest xmlns:p="urn:example:first"><section Id="sec"><same xmlns:p="urn:example:first" p:attr="1"/><other xmlns:p="urn:example:second" p:attr="2"/></section></manifest>';
      expect(part(text, '', 'section'))
        .toBe('<section xmlns:p="urn:example:first" Id="sec"><same p:attr="1"></same><other xmlns:p="urn:example:second" p:attr="2"></other></section>');
    });
  });

  describe('what a subtree carries from the elements left out', () => {
    it('carries every declaration in scope onto the element a node set starts at', () => {
      const text = `<manifest xmlns="urn:example:default" xmlns:unused="urn:example:unused" xmlns:ds="${DS}" xml:lang="en"><ds:SignedInfo Id="info" ds:type="t"><ds:Inner>text</ds:Inner></ds:SignedInfo><ds:Elsewhere/></manifest>`;
      expect(part(text, DS, 'SignedInfo'))
        .toBe(`<ds:SignedInfo xmlns="urn:example:default" xmlns:ds="${DS}" xmlns:unused="urn:example:unused" Id="info" ds:type="t" xml:lang="en"><ds:Inner>text</ds:Inner></ds:SignedInfo>`);
    });

    it('carries a language to the element a node set starts at and lets that element override it', () => {
      expect(part(BOOK_LANGUAGE, 'urn:example:book', 'chapter'))
        .toBe('<chapter xmlns="urn:example:book" Id="outer" xml:lang="en"><body Id="inner" xml:lang="fr"><line>text</line></body></chapter>');
      expect(part(BOOK_LANGUAGE, 'urn:example:book', 'body'))
        .toBe('<body xmlns="urn:example:book" Id="inner" xml:lang="fr"><line>text</line></body>');
    });

    it('leaves the elements below an element that states a language alone', () => {
      expect(whole('<book xml:lang="en"><intro><part>text</part></intro><note xml:lang="de"><other>x</other></note></book>'))
        .toBe('<book xml:lang="en"><intro><part>text</part></intro><note xml:lang="de"><other>x</other></note></book>');
    });

    it('writes no declaration of the namespace the xml prefix already holds', () => {
      const attribute: XmlAttribute = { prefix: 'xml', localName: 'lang', namespace: XML_NAMESPACE, value: 'en' };
      const bound: XmlElement = {
        kind: 'element',
        name: 'note',
        prefix: '',
        localName: 'note',
        namespace: '',
        attributes: [attribute],
        children: [],
        inScope: new Map<string, string>([['xml', XML_NAMESPACE], ['ds', DS]]),
        parent: null,
      };
      expect(new TextDecoder().decode(bytesOf(canonicalizeSubtree(bound))))
        .toBe('<note xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xml:lang="en"></note>');
    });
  });

  describe('the characters and the elements', () => {
    it('escapes the three markup characters in text and writes the two quotes as themselves', () => {
      expect(whole('<note>&lt;tag&gt; &amp; &quot;quote&quot; &apos;a&apos;</note>'))
        .toBe('<note>&lt;tag&gt; &amp; "quote" \'a\'</note>');
    });

    it('writes a tab and a line feed in text as themselves', () => {
      expect(whole('<note>a\tb\nc</note>')).toBe('<note>a\tb\nc</note>');
    });

    it('escapes a carriage return in text', () => {
      expect(new TextDecoder().decode(bytesOf(canonicalizeSubtree(handBuiltText('a\tb\nc\rd')))))
        .toBe('<note>a\tb\nc&#xD;d</note>');
    });

    it('escapes the quotation mark and the three whitespace characters in a value', () => {
      const one = handBuiltValue('say "hi" and \ttab and \nline and \rreturn and > angle');
      expect(new TextDecoder().decode(bytesOf(canonicalizeSubtree(one))))
        .toBe('<row value="say &quot;hi&quot; and &#x9;tab and &#xA;line and &#xD;return and > angle"></row>');
    });

    it('writes a CDATA section as the character data it holds', () => {
      expect(whole('<a><![CDATA[x & y]]></a>')).toBe('<a>x &amp; y</a>');
    });

    it('writes a CDATA section and the identical text as the same bytes', () => {
      expect(whole('<a><![CDATA[x & y]]></a>')).toBe(whole('<a>x &amp; y</a>'));
    });

    it('writes an element holding nothing as a start tag and an end tag', () => {
      expect(whole('<r><a/><b x="1"/></r>')).toBe('<r><a></a><b x="1"></b></r>');
    });

    it('writes a value holding nothing as a pair of quotes', () => {
      expect(whole('<r><e a="" b="1"/></r>')).toBe('<r><e a="" b="1"></e></r>');
    });

    it('writes characters beyond ASCII as the UTF-8 bytes they are', () => {
      const bytes = bytesOf(canonicalizeDocument(read('<note>café</note>')));
      expect(new TextDecoder().decode(bytes)).toBe('<note>café</note>');
      expect(bytes.byteLength).toBe(18);
    });
  });

  describe('the annotations', () => {
    it('drops a comment and keeps a processing instruction in the form without comments', () => {
      expect(whole('<r><t>a<!--cut-->b<?pi go?>c</t></r>')).toBe('<r><t>ab<?pi go?>c</t></r>');
      expect(whole('<r><t>a<!--cut-->b<?pi go?>c</t></r>', true)).toBe('<r><t>a<!--cut-->b<?pi go?>c</t></r>');
    });

    it('writes nothing of the declaration and nothing of a document type', () => {
      expect(whole('<?xml version="1.0" encoding="UTF-8"?><r><t>x</t></r>')).toBe('<r><t>x</t></r>');
    });

    it('writes a processing instruction with its target and one space before its data', () => {
      expect(whole('<r><?pi go?><t>x</t></r>')).toBe('<r><?pi go?><t>x</t></r>');
      expect(whole('<r><?pi?><t>x</t></r>')).toBe('<r><?pi?><t>x</t></r>');
    });
  });

  describe('the limit on the canonical form', () => {
    it('refuses a canonical form over the bytes this path reads', () => {
      const attributes = Array.from({ length: 8 }, (_unused, index) => `a${String(index)}="${'z'.repeat(3000)}"`).join(' ');
      const text = `<r>${`<e ${attributes}/>`.repeat(6)}</r>`;
      expect(whyOf(canonicalizeDocument(read(text)))).toMatch(/bytes/u);
    });

    it('hands back a canonical form that stays under the bytes this path reads', () => {
      const attributes = Array.from({ length: 8 }, (_unused, index) => `a${String(index)}="${'z'.repeat(400)}"`).join(' ');
      const answer = canonicalizeDocument(read(`<r>${`<e ${attributes}/>`.repeat(6)}</r>`));
      expect(bytesOf(answer).byteLength).toBeGreaterThan(0);
    });
  });
});
