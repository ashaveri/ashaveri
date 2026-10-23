import { describe, expect, it } from 'vitest';
import {
  XML_LIMITS,
  XML_NAMESPACE,
  readXml,
  type XmlCdataNode,
  type XmlCommentNode,
  type XmlDocumentNode,
  type XmlElementNode,
  type XmlInstructionNode,
  type XmlReading,
  type XmlRefusal,
  type XmlTextNode,
} from '../src/xml.js';

/**
 * What the XML subset reader takes and what it turns away.
 *
 * The shape is the one a served vendor manifest arrives in: a declaration or none, elements with attributes and
 * namespace declarations, text, CDATA, comments and processing instructions. Everything past that is refused
 * rather than carried, because a general entity can expand into bytes no one read and a document type can name a
 * system nobody fetched. Each refusal below is met before the reader is written, so the rule that answers it is
 * proven to be the reason and not a coincidence of a document that happened to fail elsewhere.
 *
 * No bytes of a served manifest are here. The documents are short, named for the rule each one met, and every
 * assertion reads a field the reader states rather than a restatement of the code that fills it.
 */

function refusalOf(read: XmlReading): XmlRefusal {
  if ('refusal' in read) {
    return read.refusal;
  }
  throw new Error(`the reader answered with a document where a refusal was asked for`);
}

function documentOf(read: XmlReading): XmlDocumentNode {
  if ('document' in read) {
    return read.document;
  }
  throw new Error(`the reader refused: ${read.refusal.reason}`);
}

function root(text: string): XmlElementNode {
  return documentOf(readXml(text)).root;
}

/** A child element by position, with the kind the reader owes that position. */
function child(element: XmlElementNode, index: number): XmlElementNode {
  const node = element.children[index];
  if (node === undefined || node.kind !== 'element') {
    throw new Error(`no element at child ${String(index)}`);
  }
  return node;
}

/** The text of the first text or CDATA node under an element, by the kind the reader states. */
function characterData(element: XmlElementNode): { readonly kind: string; readonly value: string } {
  const node = element.children.find((one) => one.kind === 'text' || one.kind === 'cdata');
  if (node === undefined || (node.kind !== 'text' && node.kind !== 'cdata')) {
    throw new Error('no character data under the element');
  }
  return { kind: node.kind, value: node.value };
}

describe('the XML subset reader', () => {
  describe('what it reads', () => {
    it('reads a declaration, one root element and its attributes', () => {
      const one = root('<?xml version="1.0" encoding="UTF-8"?><note priority="1" lang="en">text</note>');
      expect(one.prefix).toBe('');
      expect(one.local).toBe('note');
      expect(one.attributes.map((attribute) => `${attribute.prefix}:${attribute.local}=${attribute.value}`))
        .toEqual([':priority=1', ':lang=en']);
    });

    it('reads a document carrying no declaration', () => {
      const read = readXml('<a><b/></a>');
      expect(documentOf(read).declaration).toBeNull();
      expect(documentOf(read).root.local).toBe('a');
    });

    it('keeps the version, the encoding and the standalone text a declaration states', () => {
      const read = readXml('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><a/>');
      expect(documentOf(read).declaration).toEqual({ version: '1.0', encoding: 'UTF-8', standalone: 'yes' });
    });

    it('holds children in the order the document puts them', () => {
      const one = root('<a><c/><b/><d/></a>');
      expect(one.children.filter((node) => node.kind === 'element').map((node) => (node as XmlElementNode).local))
        .toEqual(['c', 'b', 'd']);
    });

    it('reads a self-closed element and one written with an end tag as the same shape', () => {
      const one = root('<a><b/><c></c></a>');
      expect(child(one, 0).children).toEqual([]);
      expect(child(one, 1).children).toEqual([]);
    });

    it('separates text, CDATA, comments and processing instructions into nodes of their own kind', () => {
      const one = root('<a>plain<![CDATA[raw]]><!--held--><?pi data?>tail</a>');
      expect(one.children.map((node) => node.kind)).toEqual(['text', 'cdata', 'comment', 'instruction', 'text']);
      expect((one.children[0] as XmlTextNode).value).toBe('plain');
      expect((one.children[1] as XmlCdataNode).value).toBe('raw');
      expect((one.children[2] as XmlCommentNode).value).toBe('held');
      expect((one.children[3] as XmlInstructionNode).target).toBe('pi');
      expect((one.children[3] as XmlInstructionNode).value).toBe('data');
    });

    it('resolves the five built-in references and nothing else', () => {
      const one = root('<a>&lt;&gt;&amp;&quot;&apos;</a>');
      expect(characterData(one).value).toBe('<>&"\'');
    });

    it('normalizes a carriage return and a line pair to one newline', () => {
      const one = root('<a>lf\r\ncr\rplain\nend</a>');
      expect(characterData(one).value).toBe('lf\ncr\nplain\nend');
    });

    it('normalizes a literal tab and a literal newline inside an attribute value to a space', () => {
      const one = root('<a b="x\ty\nz"/>');
      expect(one.attributes[0]?.value).toBe('x y z');
    });

    it('keeps a quote that arrived as a reference inside a quoted value', () => {
      const one = root('<a b="say &quot;hi&quot;"/>');
      expect(one.attributes[0]?.value).toBe('say "hi"');
    });

    it('binds a prefix declared on an ancestor', () => {
      const one = root('<a xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:b><ds:c/></ds:b></a>');
      const b = child(one, 0);
      expect(b.prefix).toBe('ds');
      expect(b.local).toBe('b');
      expect(b.uri).toBe('http://www.w3.org/2000/09/xmldsig#');
      expect(child(b, 0).uri).toBe('http://www.w3.org/2000/09/xmldsig#');
    });

    it('binds the default namespace and lets an inner element rebind it', () => {
      const one = root('<a xmlns="urn:outer"><b xmlns="urn:inner"/><c/></a>');
      expect(one.uri).toBe('urn:outer');
      expect(child(one, 0).uri).toBe('urn:inner');
      expect(child(one, 1).uri).toBe('urn:outer');
    });

    it('records no namespace for an unprefixed attribute', () => {
      const one = root('<a xmlns="urn:outer" b="1"/>');
      expect(one.attributes[0]?.prefix).toBe('');
      expect(one.attributes[0]?.uri).toBe('');
    });

    it('binds the xml prefix without a declaration naming it', () => {
      const one = root('<a xml:lang="en"/>');
      expect(one.attributes[0]?.prefix).toBe('xml');
      expect(one.attributes[0]?.uri).toBe(XML_NAMESPACE);
    });

    it('keeps the declarations of an element in the order they were written', () => {
      const one = root('<a xmlns:z="urn:z" xmlns="urn:d" xmlns:a="urn:a"/>');
      expect(one.namespaces).toEqual([
        { prefix: 'z', uri: 'urn:z' },
        { prefix: '', uri: 'urn:d' },
        { prefix: 'a', uri: 'urn:a' },
      ]);
    });

    it('points an element at the element that holds it', () => {
      const one = root('<a xmlns:ds="urn:ds"><ds:b><ds:c/></ds:b></a>');
      const b = child(one, 0);
      const c = child(b, 0);
      expect(c.parent).toBe(b);
      expect(b.parent).toBe(one);
      expect(one.parent).toBeNull();
    });

    it('holds the markup around the root element apart from its children', () => {
      const read = readXml('<!--before--><?pi one?><a/><!--after--><?pi two?>');
      const doc = documentOf(read);
      expect(doc.prologue.map((node) => node.kind)).toEqual(['comment', 'instruction']);
      expect(doc.epilogue.map((node) => node.kind)).toEqual(['comment', 'instruction']);
      expect(doc.root.children).toEqual([]);
    });

    it('reads a declaration without a space before the close', () => {
      const read = readXml('<?xml version="1.0"?><a/>');
      expect(documentOf(read).declaration).toEqual({ version: '1.0', encoding: '', standalone: null });
    });

    it('accepts a byte order mark, which the encoding layer leaves behind', () => {
      const read = readXml('\uFEFF<a/>');
      expect(documentOf(read).root.local).toBe('a');
    });
  });

  describe('what it refuses, and why', () => {
    it('refuses a document type declaration before anything else in the document is read', () => {
      const refusal = refusalOf(readXml(
        '<!DOCTYPE a [ <!ENTITY b "whatever"> ]><a>&b;</a>',
      ));
      expect(refusal.kind).toBe('construct');
      expect(refusal.reason).toMatch(/document type declaration/u);
    });

    it('refuses a document type declaration met inside the content', () => {
      const refusal = refusalOf(readXml('<a><!DOCTYPE html></a>'));
      expect(refusal.kind).toBe('construct');
      expect(refusal.reason).toMatch(/document type declaration/u);
    });

    it('refuses an entity declaration on its own', () => {
      const refusal = refusalOf(readXml('<a><!ENTITY b "x"/></a>'));
      expect(refusal.kind).toBe('construct');
      expect(refusal.reason).toMatch(/entity declaration/u);
    });

    it('refuses an entity reference that is not one of the five built-in ones', () => {
      const refusal = refusalOf(readXml('<a>&nbsp;</a>'));
      expect(refusal.kind).toBe('construct');
      expect(refusal.reason).toMatch(/entity reference/u);
      expect(refusal.reason).toContain('nbsp');
    });

    it('refuses a character reference in either spelling', () => {
      const decimal = refusalOf(readXml('<a>&#10;</a>'));
      expect(decimal.kind).toBe('construct');
      expect(decimal.reason).toMatch(/character reference/u);
      const hexadecimal = refusalOf(readXml('<a>&#x41;</a>'));
      expect(hexadecimal.kind).toBe('construct');
      expect(hexadecimal.reason).toMatch(/character reference/u);
    });

    it('refuses an ampersand that begins nothing', () => {
      const refusal = refusalOf(readXml('<a>R&D</a>'));
      expect(refusal.kind).toBe('unreadable');
      expect(refusal.reason).toMatch(/ampersand/u);
    });

    it('refuses an element left open when the document ends', () => {
      const refusal = refusalOf(readXml('<a><b>text'));
      expect(refusal.kind).toBe('unreadable');
      expect(refusal.reason).toMatch(/open/u);
    });

    it('refuses an end tag naming another element than the one open', () => {
      const refusal = refusalOf(readXml('<a><b></a></a>'));
      expect(refusal.kind).toBe('unreadable');
      expect(refusal.reason).toMatch(/</u);
      expect(refusal.reason).toContain('b');
      expect(refusal.reason).toContain('a');
    });

    it('refuses an end tag with nothing open', () => {
      const refusal = refusalOf(readXml('</a>'));
      expect(refusal.kind).toBe('unreadable');
    });

    it('refuses a second root element', () => {
      const refusal = refusalOf(readXml('<a/><b/>'));
      expect(refusal.kind).toBe('unreadable');
      expect(refusal.reason).toMatch(/root/u);
    });

    it('refuses text after the root element', () => {
      const refusal = refusalOf(readXml('<a/>trailing'));
      expect(refusal.kind).toBe('unreadable');
      expect(refusal.reason).toMatch(/after the root/u);
    });

    it('refuses a prefix no declaration binds, on an element and on an attribute', () => {
      const onElement = refusalOf(readXml('<ds:a/>'));
      expect(onElement.kind).toBe('namespace');
      expect(onElement.reason).toMatch(/ds/u);
      const onAttribute = refusalOf(readXml('<a ds:b="1"/>'));
      expect(onAttribute.kind).toBe('namespace');
      expect(onAttribute.reason).toMatch(/ds/u);
    });

    it('refuses a prefixed namespace bound to nothing', () => {
      const refusal = refusalOf(readXml('<a xmlns:p=""/>'));
      expect(refusal.kind).toBe('namespace');
    });

    it('refuses the xml prefix bound to another namespace', () => {
      const refusal = refusalOf(readXml('<a xmlns:xml="urn:other"><b/></a>'));
      expect(refusal.kind).toBe('namespace');
      expect(refusal.reason).toContain('xml');
    });

    it('refuses two attributes with the same name', () => {
      const refusal = refusalOf(readXml('<a b="1" b="2"/>'));
      expect(refusal.kind).toBe('unreadable');
      expect(refusal.reason).toMatch(/twice/u);
    });

    it('refuses a closing bracket pair in content that is not a CDATA section', () => {
      const refusal = refusalOf(readXml('<a>bad]]>run</a>'));
      expect(refusal.kind).toBe('unreadable');
    });

    it('refuses a comment carrying two hyphens', () => {
      const refusal = refusalOf(readXml('<a><!--not--allowed--></a>'));
      expect(refusal.kind).toBe('unreadable');
    });

    it('refuses a processing instruction targeting xml', () => {
      const refusal = refusalOf(readXml('<?xml version="1.0"?><a/><?XML version="1.0"?>'));
      expect(refusal.kind).toBe('construct');
      expect(refusal.reason).toMatch(/processing instruction/u);
    });

    it('refuses a name that starts where a name may not', () => {
      const refusal = refusalOf(readXml('<1a/>'));
      expect(refusal.kind).toBe('unreadable');
      expect(refusal.reason).toMatch(/name/u);
    });

    it('refuses a tag never closed', () => {
      const refusal = refusalOf(readXml('<a b="1"'));
      expect(refusal.kind).toBe('unreadable');
    });

    it('refuses a CDATA section never closed', () => {
      const refusal = refusalOf(readXml('<a><![CDATA[run on'));
      expect(refusal.kind).toBe('unreadable');
    });

    it('refuses a raw < inside an attribute value', () => {
      const refusal = refusalOf(readXml('<a b="x<y"/>'));
      expect(refusal.kind).toBe('unreadable');
    });

    it('refuses a declaration naming an encoding other than UTF-8', () => {
      const refusal = refusalOf(readXml('<?xml version="1.0" encoding="ISO-8859-1"?><a/>'));
      expect(refusal.kind).toBe('construct');
      expect(refusal.reason).toMatch(/ISO-8859-1/u);
    });

    it('refuses a declaration naming a version this reader does not hold', () => {
      const refusal = refusalOf(readXml('<?xml version="1.1"?><a/>'));
      expect(refusal.kind).toBe('construct');
      expect(refusal.reason).toMatch(/version/u);
    });

    it('refuses a document that is not markup at all', () => {
      const refusal = refusalOf(readXml('not xml'));
      expect(refusal.kind).toBe('unreadable');
    });

    it('refuses an empty document', () => {
      expect(refusalOf(readXml('')).kind).toBe('unreadable');
    });
  });

  describe('the limits this path states', () => {
    function nested(depth: number): string {
      return `${'<a>'.repeat(depth)}</a>${'</a>'.repeat(depth)}`;
    }

    it('refuses an element nesting deeper than the reader holds', () => {
      const within = readXml(nested(XML_LIMITS.maxDepth));
      expect('document' in within, 'the ceiling itself is readable').toBe(true);
      const refusal = refusalOf(readXml(nested(XML_LIMITS.maxDepth + 1)));
      expect(refusal.kind).toBe('ceiling');
      expect(refusal.reason).toMatch(/depth/u);
      expect(refusal.reason).toContain(String(XML_LIMITS.maxDepth));
    });

    it('refuses more nodes than the reader counts', () => {
      const text = `<r>${'<x/>'.repeat(XML_LIMITS.maxNodes)}</r>`;
      const refusal = refusalOf(readXml(text));
      expect(refusal.kind).toBe('ceiling');
      expect(refusal.reason).toMatch(/nodes/u);
    });

    it('refuses more attributes on one element than the reader reads', () => {
      const attributes = Array.from({ length: XML_LIMITS.maxAttributes + 1 }, (_unused, index) => `a${String(index)}="1"`).join(' ');
      const refusal = refusalOf(readXml(`<r ${attributes}/>`));
      expect(refusal.kind).toBe('ceiling');
      expect(refusal.reason).toMatch(/attributes/u);
    });

    it('refuses more namespace declarations on one element than the reader binds', () => {
      const declared = Array.from({ length: XML_LIMITS.maxNamespaces + 1 }, (_unused, index) => `xmlns:p${String(index)}="urn:${String(index)}"`).join(' ');
      const refusal = refusalOf(readXml(`<r ${declared}/>`));
      expect(refusal.kind).toBe('ceiling');
      expect(refusal.reason).toMatch(/namespace declarations/u);
    });

    it('refuses a name longer than the reader carries', () => {
      const name = 'x'.repeat(XML_LIMITS.maxNameLength + 1);
      const refusal = refusalOf(readXml(`<${name}/>`));
      expect(refusal.kind).toBe('ceiling');
      expect(refusal.reason).toMatch(/name/u);
    });

    it('refuses a run of text longer than the reader holds', () => {
      const refusal = refusalOf(readXml(`<r>${'y'.repeat(XML_LIMITS.maxTextLength + 1)}</r>`));
      expect(refusal.kind).toBe('ceiling');
      expect(refusal.reason).toMatch(/text/u);
    });
  });
});
