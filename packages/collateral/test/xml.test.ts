import { describe, expect, it } from 'vitest';
import {
  XML_CEILINGS,
  attributeOf,
  canonicalizeDocument,
  childElements,
  collectElements,
  elementText,
  readXml,
  type ReadOutcome,
  type XmlDocument,
  type XmlElement,
  type XmlNode,
} from '../src/xml.js';

/**
 * What the XML subset reader takes and what it turns away.
 *
 * The shape is the one a served vendor manifest arrives in: a declaration or none, elements with attributes and
 * namespace declarations, text, CDATA, comments and processing instructions. Everything past that is refused
 * rather than carried, because a general entity can expand into bytes no one read and a document type can name a
 * system nobody fetched. Each refusal below is met by a document that spells one rule and nothing else, so the
 * answer that names it is proven to be the reason rather than a coincidence of a document that failed elsewhere.
 *
 * Three of these rules are stricter than a browser would be. A declaration of the reserved `xml` and `xmlns`
 * prefixes is refused even where it restates the namespace those prefixes already hold, a prefixed declaration
 * binding to nothing is refused rather than read as an unbinding, and a namespace name that is not an absolute
 * reference is refused. Each is legal somewhere, and none of them has a business reaching a signature digest: a
 * verifier that imitates the loosest reader it has never met is a verifier that cannot name its own rules.
 *
 * The namespace XML reserves for the `xml` prefix is spelled out below rather than read from the module, so a
 * change to what the reader binds has to fail a case here. The ceilings are read from `XML_CEILINGS` and each is
 * met twice: the document at the ceiling is read, the document past it is refused with the number stated. No
 * bytes of a served manifest are in this file.
 */

const XML_NAMESPACE = 'http://www.w3.org/XML/1998/namespace';

function whyOf(answer: ReadOutcome): string {
  if ('document' in answer) {
    throw new Error('the reader handed back a document where a refusal was asked for');
  }
  return answer.why;
}

function documentOf(answer: ReadOutcome): XmlDocument {
  if ('why' in answer) {
    throw new Error(`the reader refused the document a case asked it to read: ${answer.why}`);
  }
  return answer.document;
}

function root(text: string): XmlElement {
  return documentOf(readXml(text)).root;
}

/** A child element by position, with the kind the reader owes that position. */
function child(element: XmlElement, index: number): XmlElement {
  const node = element.children[index];
  if (node === undefined || node.kind !== 'element') {
    throw new Error(`no element at child ${String(index)}`);
  }
  return node;
}

/** The characters of the first child, which the cases below hand the reader as text or as CDATA. */
function firstText(element: XmlElement): string {
  const node = element.children[0];
  if (node === undefined || node.kind !== 'text') {
    throw new Error('no text node as the first child');
  }
  return node.characters;
}

function kinds(nodes: readonly XmlNode[]): readonly string[] {
  return nodes.map((node) => node.kind);
}

/** A document of `count` elements each holding one text node of `characters`, for the canonical form ceilings. */
function widened(count: number, characters: string): string {
  return `<r>${`<a>${characters.repeat(XML_CEILINGS.maxTextCharacters)}</a>`.repeat(count)}</r>`;
}

function canonicalBytes(text: string): string {
  const answer = canonicalizeDocument(documentOf(readXml(text)));
  if ('bytes' in answer) {
    return new TextDecoder().decode(answer.bytes);
  }
  throw new Error(`the canonicalizer refused: ${answer.why}`);
}

function canonicalWhy(text: string): string {
  const answer = canonicalizeDocument(documentOf(readXml(text)));
  if ('why' in answer) {
    return answer.why;
  }
  throw new Error('the canonicalizer handed back bytes where a refusal was asked for');
}

describe('the XML subset reader', () => {
  describe('what it hands back', () => {
    it('reads the document element with its name split the way a namespace is read from it', () => {
      const one = root('<ds:note xmlns:ds="http://www.w3.org/2000/09/xmldsig#" priority="1">text</ds:note>');
      expect(one.kind).toBe('element');
      expect(one.name).toBe('ds:note');
      expect(one.prefix).toBe('ds');
      expect(one.localName).toBe('note');
      expect(one.namespace).toBe('http://www.w3.org/2000/09/xmldsig#');
      expect(one.attributes.length).toBe(1);
      const priority = one.attributes[0];
      if (priority === undefined) {
        throw new Error('the reader dropped the attribute the start tag wrote');
      }
      expect([priority.prefix, priority.localName, priority.namespace, priority.value]).toEqual(['', 'priority', '', '1']);
      expect(firstText(one)).toBe('text');
    });

    it('holds the children in the order the document puts them', () => {
      const one = root('<a><c/><b/><d/></a>');
      expect(one.children.map((node) => (node.kind === 'element' ? node.name : node.kind))).toEqual(['c', 'b', 'd']);
    });

    it('reads a self-closed element and one written with an end tag as the same shape', () => {
      const one = root('<a><b/><c></c></a>');
      expect(child(one, 0).children).toEqual([]);
      expect(child(one, 1).children).toEqual([]);
    });

    it('folds a CDATA section into the text around it as one node', () => {
      const one = root('<a>x<![CDATA[y & z]]>w</a>');
      expect(kinds(one.children)).toEqual(['text']);
      expect(firstText(one)).toBe('xy & zw');
    });

    it('keeps text either side of a comment as the two nodes they are', () => {
      const one = root('<a>x<!--cut-->y</a>');
      expect(kinds(one.children)).toEqual(['text', 'comment', 'text']);
    });

    it('holds a comment and an instruction as nodes carrying what they were written with', () => {
      const one = root('<a>t<!--held--><?pi data?>u</a>');
      expect(kinds(one.children)).toEqual(['text', 'comment', 'instruction', 'text']);
      const comment = one.children[1];
      const instruction = one.children[2];
      if (comment === undefined || comment.kind !== 'comment' || instruction === undefined || instruction.kind !== 'instruction') {
        throw new Error('the reader did not hand back the annotation the document carried');
      }
      expect(comment.characters).toBe('held');
      expect(instruction.target).toBe('pi');
      expect(instruction.data).toBe('data');
    });

    it('holds the instruction written with nothing after its target as carrying no data', () => {
      const one = root('<a><?pi?></a>');
      const instruction = one.children[0];
      if (instruction === undefined || instruction.kind !== 'instruction') {
        throw new Error('the reader did not hand back the instruction');
      }
      expect(instruction.target).toBe('pi');
      expect(instruction.data).toBe('');
    });

    it('holds the annotations around the document element apart from its children', () => {
      const document = documentOf(readXml('<!--before--><?pi one?><a/><!--after--><?pi two?>'));
      expect(kinds(document.before)).toEqual(['comment', 'instruction']);
      expect(kinds(document.after)).toEqual(['comment', 'instruction']);
      expect(document.root.children).toEqual([]);
    });

    it('drops the declaration once it has read the version and the encoding out of it', () => {
      const document = documentOf(readXml('<?xml version="1.0" encoding="UTF-8"?><a/>'));
      expect(kinds(document.before)).toEqual([]);
      expect(document.root.name).toBe('a');
    });

    it('reads a declaration written with single quotes and no space before its close', () => {
      expect(root("<?xml version='1.0'?><a/>").name).toBe('a');
    });

    it('settles the line endings of the whole input before parsing', () => {
      expect(firstText(root('<a>lf\r\ncr\rplain\nend</a>'))).toBe('lf\ncr\nplain\nend');
    });

    it('resolves the five predefined entities', () => {
      expect(firstText(root('<a>&lt;&gt;&amp;&quot;&apos;</a>'))).toBe('<>&"\'');
    });

    it('resolves a character reference in either base', () => {
      expect(firstText(root('<a>&#65;&#x41;&#x4a;&#256;</a>'))).toBe('AAJĀ');
    });

    it('keeps a carriage return that arrived as a reference, which the line endings never touch', () => {
      expect(firstText(root('<a>x&#xD;y</a>'))).toBe('x\ry');
    });

    it('keeps a quote that arrived as a reference inside a quoted value', () => {
      const one = root('<a b="say &quot;hi&quot;"/>');
      expect(one.attributes[0]?.value).toBe('say "hi"');
    });

    it('binds a prefix declared on an ancestor and carries the scope down', () => {
      const one = root('<a xmlns:ds="urn:outer"><ds:b><ds:c/></ds:b></a>');
      const b = child(one, 0);
      expect(b.namespace).toBe('urn:outer');
      expect(b.inScope.get('ds')).toBe('urn:outer');
      expect(child(b, 0).namespace).toBe('urn:outer');
      expect(one.inScope.get('xml')).toBe(XML_NAMESPACE);
    });

    it('binds the default namespace and lets an element reset it without resetting its sibling', () => {
      const one = root('<a xmlns="urn:outer"><b xmlns=""/><c/></a>');
      expect(one.namespace).toBe('urn:outer');
      expect(child(one, 0).namespace).toBe('');
      expect(child(one, 0).inScope.has('')).toBe(false);
      expect(child(one, 1).namespace).toBe('urn:outer');
    });

    it('gives an unprefixed attribute no namespace even under a default', () => {
      const one = root('<a xmlns="urn:outer" b="1"/>');
      expect(one.attributes[0]?.prefix).toBe('');
      expect(one.attributes[0]?.namespace).toBe('');
    });

    it('binds the xml prefix without a declaration naming it', () => {
      const one = root('<a xml:lang="en"/>');
      expect(one.attributes[0]?.prefix).toBe('xml');
      expect(one.attributes[0]?.namespace).toBe(XML_NAMESPACE);
      expect(one.inScope.get('xml')).toBe(XML_NAMESPACE);
    });

    it('binds a prefix onto an attribute the way it binds one onto an element', () => {
      const one = root('<a xmlns:ds="urn:ex" ds:c="1"/>');
      expect(one.attributes[0]?.prefix).toBe('ds');
      expect(one.attributes[0]?.localName).toBe('c');
      expect(one.attributes[0]?.namespace).toBe('urn:ex');
    });

    it('keeps the scope of a declaration to the element that wrote it', () => {
      const one = root('<a xmlns:ds="urn:outer"><b xmlns:ds="urn:inner"><ds:c/></b><ds:d/></a>');
      expect(child(child(one, 0), 0).namespace).toBe('urn:inner');
      expect(child(one, 1).namespace).toBe('urn:outer');
    });

    it('points an element at the element that holds it', () => {
      const one = root('<a><b><c/></b></a>');
      const b = child(one, 0);
      expect(child(b, 0).parent).toBe(b);
      expect(b.parent).toBe(one);
      expect(one.parent).toBeNull();
    });

    it('accepts a byte order mark, which the encoding layer leaves behind', () => {
      expect(root('\uFEFF<a/>').name).toBe('a');
    });
  });

  describe('what it refuses, and why', () => {
    it('refuses a document type declaration in the prolog before reading any further', () => {
      expect(whyOf(readXml('<!DOCTYPE a [ <!ENTITY b "whatever"> ]><a/>&b;')))
        .toMatch(/document type declaration/u);
    });

    it('refuses a document type declaration met inside the content', () => {
      expect(whyOf(readXml('<a><!DOCTYPE html></a>'))).toMatch(/document type declaration/u);
    });

    it('refuses an entity declaration in either place', () => {
      expect(whyOf(readXml('<a><!ENTITY b "x"/></a>'))).toMatch(/entity declaration/u);
      expect(whyOf(readXml('<!ENTITY b "x"><a/>'))).toMatch(/entity declaration/u);
    });

    it('refuses a reference to an entity the document never declares', () => {
      expect(whyOf(readXml('<a>&nbsp;</a>'))).toMatch(/undeclared entity nbsp/u);
    });

    it('refuses a reference that is not closed', () => {
      expect(whyOf(readXml('<a>&amp</a>'))).toMatch(/the reference to amp is not closed/u);
      expect(whyOf(readXml('<a>R&D</a>'))).toMatch(/the reference to D is not closed/u);
    });

    it('refuses a character reference that states no character', () => {
      expect(whyOf(readXml('<a>&#x;</a>'))).toMatch(/states no character/u);
      expect(whyOf(readXml('<a>&#;</a>'))).toMatch(/states no character/u);
    });

    it('refuses a character reference naming a character XML does not allow', () => {
      expect(whyOf(readXml('<a>&#0;</a>'))).toMatch(/not a character XML allows/u);
      expect(whyOf(readXml('<a>&#xD800;</a>'))).toMatch(/not a character XML allows/u);
    });

    it('refuses a value carrying literal whitespace, which the readers feeding the canonical form settle differently', () => {
      expect(whyOf(readXml('<a b="x\ty"/>'))).toMatch(/literal whitespace/u);
      expect(whyOf(readXml('<a b="x\ny"/>'))).toMatch(/literal whitespace/u);
    });

    it('refuses a value carrying a line ending, which is a literal whitespace by the time it is read', () => {
      expect(whyOf(readXml('<a b="x\r\ny"/>'))).toMatch(/literal whitespace/u);
    });

    it('reads the same whitespace through a reference, which is the spelling the canonical form states a rule for', () => {
      expect(root('<a b="x&#9;y&#10;z&#13;w"/>').attributes[0]?.value).toBe('x\ty\nz\rw');
    });

    it('refuses an element left open when the document ends', () => {
      expect(whyOf(readXml('<a><b>text'))).toMatch(/runs out before its element is closed/u);
    });

    it('refuses a start tag left open when the document ends', () => {
      expect(whyOf(readXml('<a b="1"'))).toMatch(/the start tag of a is not closed/u);
      expect(whyOf(readXml('<a b="1" '))).toMatch(/the start tag of a is not closed/u);
    });

    it('refuses an end tag naming another element than the one open', () => {
      expect(whyOf(readXml('<a><b></a></a>'))).toMatch(/the element b is closed by a/u);
    });

    it('refuses an end tag with nothing open', () => {
      expect(whyOf(readXml('</a>'))).toMatch(/does not begin with a name character/u);
    });

    it('refuses a second document element', () => {
      expect(whyOf(readXml('<a/><b/>'))).toMatch(/second document element/u);
    });

    it('refuses content after the document element', () => {
      expect(whyOf(readXml('<a/>trailing'))).toMatch(/content after the document element/u);
    });

    it('refuses text before the document element and a document carrying none', () => {
      expect(whyOf(readXml('not xml'))).toMatch(/prolog carries text before the document element/u);
      expect(whyOf(readXml(''))).toMatch(/carries no document element/u);
    });

    it('refuses a prefix no declaration binds, on an element and on an attribute', () => {
      expect(whyOf(readXml('<ds:a/>'))).toMatch(/the element ds:a uses the undeclared prefix ds/u);
      expect(whyOf(readXml('<a ds:b="1"/>'))).toMatch(/the attribute ds:b uses the undeclared prefix ds/u);
    });

    it('refuses a declaration of either reserved prefix, including one that restates what it already holds', () => {
      expect(whyOf(readXml('<a xmlns:xml="urn:other"><b/></a>'))).toMatch(/xml prefix is not available/u);
      expect(whyOf(readXml(`<a xmlns:xml="${XML_NAMESPACE}"><b/></a>`))).toMatch(/xml prefix is not available/u);
      expect(whyOf(readXml('<a xmlns:xmlns="urn:other"><b/></a>'))).toMatch(/xmlns prefix is not available/u);
    });

    it('refuses a prefixed declaration that states no namespace', () => {
      expect(whyOf(readXml('<a xmlns:p=""/>'))).toMatch(/declaration of the prefix p states no namespace/u);
    });

    it('refuses a namespace name that is not an absolute reference', () => {
      expect(whyOf(readXml('<a xmlns:p="relative/path"/>'))).toMatch(/xmlns:p is not an absolute reference/u);
      expect(whyOf(readXml('<a xmlns:p="#same"/>'))).toMatch(/is not an absolute reference/u);
    });

    it('refuses two attributes written with the same name', () => {
      expect(whyOf(readXml('<a b="1" b="2"/>'))).toMatch(/the name b is written twice on a/u);
    });

    it('refuses an attribute that states no value', () => {
      expect(whyOf(readXml('<a b/>'))).toMatch(/the attribute b of a states no value/u);
    });

    it('refuses a value that is not quoted, and one that is never closed', () => {
      expect(whyOf(readXml('<a b=x/>'))).toMatch(/not written as quoted text/u);
      expect(whyOf(readXml('<a b="x>'))).toMatch(/attribute value is not closed/u);
    });

    it('refuses a raw angle bracket inside a value', () => {
      expect(whyOf(readXml('<a b="x<y"/>'))).toMatch(/bare angle bracket/u);
    });

    it('refuses two names in a start tag with no space between them', () => {
      expect(whyOf(readXml('<a b="1"c="2"/>'))).toMatch(/no space before another name/u);
    });

    it('refuses a closing bracket pair in content that is not a CDATA section', () => {
      expect(whyOf(readXml('<a>bad]]>run</a>'))).toMatch(/closes a section it did not open/u);
    });

    it('refuses a CDATA section never closed', () => {
      expect(whyOf(readXml('<a><![CDATA[run on'))).toMatch(/CDATA section is not closed/u);
    });

    it('refuses a comment carrying the two hyphens that would close it, and one never closed', () => {
      expect(whyOf(readXml('<a><!--not--allowed--></a>'))).toMatch(/two hyphens that would close it/u);
      expect(whyOf(readXml('<a><!--run on</a>'))).toMatch(/comment is not closed/u);
    });

    it('refuses an instruction taking the reserved target and one never closed', () => {
      expect(whyOf(readXml('<a/><?XML version="1.0"?>'))).toMatch(/reserved target xml/u);
      expect(whyOf(readXml('<a><?pi run on'))).toMatch(/the instruction targeting pi is not closed/u);
    });

    it('refuses a name that starts where a name may not', () => {
      expect(whyOf(readXml('<1a/>'))).toMatch(/does not begin with a name character/u);
    });

    it('refuses a name spelling more than one prefix', () => {
      expect(whyOf(readXml('<a:b:c/>'))).toMatch(/not one prefix and one local name/u);
      expect(whyOf(readXml('<a:/></a:>'))).toMatch(/not one prefix and one local name/u);
    });

    it('refuses a declaration stating a version this path does not read', () => {
      expect(whyOf(readXml('<?xml version="1.1"?><a/>'))).toMatch(/states version 1.1/u);
      expect(whyOf(readXml('<?xml encoding="UTF-8"?><a/>'))).toMatch(/states no version/u);
    });

    it('refuses a declaration stating an encoding other than UTF-8 and reads the name in any case', () => {
      expect(whyOf(readXml('<?xml version="1.0" encoding="ISO-8859-1"?><a/>'))).toMatch(/reads UTF-8 alone/u);
      expect(root('<?xml version="1.0" encoding="utf-8"?><a/>').name).toBe('a');
    });

    it('refuses a declaration stating a standalone answer version 1.0 does not allow', () => {
      expect(whyOf(readXml('<?xml version="1.0" standalone="maybe"?><a/>'))).toMatch(/standalone maybe/u);
      expect(root('<?xml version="1.0" standalone="yes"?><a/>').name).toBe('a');
    });

    it('refuses a declaration carrying a member the version states nowhere', () => {
      expect(whyOf(readXml('<?xml version="1.0" foo="bar"?><a/>'))).toMatch(/carries the member foo/u);
    });

    it('refuses a declaration never closed', () => {
      expect(whyOf(readXml('<?xml version="1.0"'))).toMatch(/XML declaration is not closed/u);
    });

    it('refuses a name after the declaration marker that is not a member it can read', () => {
      expect(whyOf(readXml('<?xmlfoo bar?>'))).toMatch(/no value for foo/u);
    });
  });

  describe('the ceilings it states', () => {
    function nested(depth: number): string {
      return '<a>'.repeat(depth) + '</a>'.repeat(depth);
    }

    it('reads the deepest nesting it holds and refuses one level past it', () => {
      expect(root(nested(XML_CEILINGS.maxDepth)).name).toBe('a');
      expect(whyOf(readXml(nested(XML_CEILINGS.maxDepth + 1))))
        .toMatch(`nests deeper than the ${String(XML_CEILINGS.maxDepth)} levels`);
    });

    it('counts the elements of a document and refuses one past the count it holds', () => {
      const at = `<r>${'<x/>'.repeat(XML_CEILINGS.maxElements - 1)}</r>`;
      expect(child(root(at), 0).name).toBe('x');
      const past = `<r>${'<x/>'.repeat(XML_CEILINGS.maxElements)}</r>`;
      expect(whyOf(readXml(past))).toMatch(`more than the ${String(XML_CEILINGS.maxElements)} elements`);
    });

    it('counts attributes and declarations together on one element', () => {
      const attributes = Array.from({ length: XML_CEILINGS.maxAttributesPerElement }, (_unused, index) => `a${String(index)}="1"`).join(' ');
      expect(root(`<r ${attributes}/>`).attributes.length).toBe(XML_CEILINGS.maxAttributesPerElement);
      const declarations = Array.from({ length: XML_CEILINGS.maxAttributesPerElement }, (_unused, index) => `xmlns:p${String(index)}="urn:${String(index)}"`).join(' ');
      expect(whyOf(readXml(`<r ${declarations} one="more"/>`)))
        .toMatch(`more than the ${String(XML_CEILINGS.maxAttributesPerElement)} attributes`);
    });

    it('refuses a name longer than the characters it carries, the prefix included', () => {
      const at = 'x'.repeat(XML_CEILINGS.maxNameCharacters);
      expect(root(`<${at}/>`).name.length).toBe(XML_CEILINGS.maxNameCharacters);
      expect(whyOf(readXml(`<p:${'x'.repeat(XML_CEILINGS.maxNameCharacters)}/>`)))
        .toMatch(`over the ${String(XML_CEILINGS.maxNameCharacters)} characters`);
    });

    it('refuses a run of text longer than the characters it holds', () => {
      expect(firstText(root(`<r>${'y'.repeat(XML_CEILINGS.maxTextCharacters)}</r>`)).length)
        .toBe(XML_CEILINGS.maxTextCharacters);
      expect(whyOf(readXml(`<r>${'y'.repeat(XML_CEILINGS.maxTextCharacters + 1)}</r>`)))
        .toMatch(`over the ${String(XML_CEILINGS.maxTextCharacters)} characters`);
    });

    it('refuses a value longer than the characters it holds', () => {
      const at = 'y'.repeat(XML_CEILINGS.maxAttributeCharacters);
      expect(root(`<r a="${at}"/>`).attributes[0]?.value.length).toBe(XML_CEILINGS.maxAttributeCharacters);
      expect(whyOf(readXml(`<r a="${'y'.repeat(XML_CEILINGS.maxAttributeCharacters + 1)}"/>`)))
        .toMatch(`over the ${String(XML_CEILINGS.maxAttributeCharacters)} characters`);
    });

    it('refuses a canonical form whose characters pass the bytes it hands back', () => {
      expect(new TextEncoder().encode(canonicalBytes(widened(7, 'x'))).byteLength).toBe(114744);
      expect(canonicalWhy(widened(8, 'x'))).toMatch(`is over the ${String(XML_CEILINGS.maxCanonicalBytes)} bytes`);
    });

    it('refuses a canonical form whose bytes pass the ceiling while its characters stay under it', () => {
      const decoded = canonicalBytes(widened(3, 'é'));
      expect(decoded.length).toBe(49180);
      expect(new TextEncoder().encode(decoded).byteLength).toBe(98332);
      expect(canonicalWhy(widened(4, 'é'))).toMatch('the canonical form is 131107 bytes');
    });
  });

  describe('the readings a caller takes from a tree', () => {
    it('collects every element in document order with the document element first', () => {
      const document = documentOf(readXml('<r><a><b/></a><c/></r>'));
      expect(collectElements(document).map((one) => one.name)).toEqual(['r', 'a', 'b', 'c']);
    });

    it('reads the text an element holds and refuses to read past anything that is not text', () => {
      expect(elementText(root('<a>x y</a>'))).toBe('x y');
      expect(elementText(root('<a></a>'))).toBe('');
      expect(elementText(root('<a>x<b/></a>'))).toBeNull();
      expect(elementText(root('<a>x<!--cut-->y</a>'))).toBeNull();
    });

    it('reads a value by the name it carries in no namespace and will not read a prefixed one', () => {
      const one = root('<a xmlns:ds="urn:ex" version="1" ds:version="2"/>');
      expect(attributeOf(one, 'version')).toBe('1');
      const prefixed = root('<a xmlns:ds="urn:ex" ds:version="2"/>');
      expect(attributeOf(prefixed, 'version')).toBeNull();
    });

    it('reads the child elements naming one namespace and one local name in the order they stand', () => {
      const one = root('<r xmlns:ds="urn:ex"><ds:c/><other/><ds:c/><x><ds:c/></x></r>');
      expect(childElements(one, 'urn:ex', 'c').map((one2) => one2.name)).toEqual(['ds:c', 'ds:c']);
      expect(childElements(one, 'urn:ex', 'missing')).toEqual([]);
      expect(childElements(one, '', 'other').map((one2) => one2.name)).toEqual(['other']);
    });
  });
});
