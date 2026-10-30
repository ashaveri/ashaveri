/**
 * The XML subset this package reads, and Canonical XML version 1.1 as rendered from it.
 *
 * Nothing in this package's dependency set reads XML, and a Reference Integrity Manifest is SWID XML whose
 * signature is taken over a canonicalized element, so both halves are weighed here rather than by a third party
 * whose rules a caller could not name. Each is small on purpose: the only document this path canonicalizes is the
 * one the profile in `rim.ts` names, and every rule stated below is a rule that profile can be held to.
 *
 * The subset is XML 1.0 without a document type declaration. That declaration is refused where it is met rather
 * than read, because it is the one input that changes what the bytes mean before parsing: it declares entities
 * whose replacement text enters the canonical form, it declares attribute types whose normalization a reader
 * would have to imitate, and it points at content the reader has not fetched. A reference to any entity other
 * than the five XML predefines is refused for the same reason, so what the canonicalizer sees is always the text
 * in front of it, and a CDATA section is replaced with the characters it held, as the canonical form requires.
 *
 * The characters read as name characters are the ASCII ones XML allows in a name plus the colon that separates a
 * prefix from a local name: a name outside that set is refused rather than guessed at, which keeps a look-alike
 * from reaching a comparison. The input is UTF-8 text the caller already decoded, since that is the encoding a
 * manifest arrives in and a declaration naming another is refused; a leading byte order mark is an artifact of
 * that encoding and is dropped, as the canonical form carries none.
 *
 * Whitespace reaches a value through a character reference and not as itself. The canonical form states a rule for
 * a value holding a tab, a line feed or a carriage return, but the parsers feeding it disagree about whether that
 * character is in the value at all when the document spelled it literally rather than as a reference, so a value
 * carrying literal whitespace is refused: bytes whose digest depends on which parser a signer used are not a fact
 * a verifier can hand back. A reference is settled by the reader into the character it names, which is what the
 * canonical form then escapes, so both readings of the rule agree on those bytes.
 *
 * The ceilings are this path's limit and not the format's: a document over one of them is refused before the
 * canonical form is built, because the work a document can ask of a verifier is itself something to bound.
 */

/** What one document may hold before this path refuses it as more than it weighs. */
export const XML_CEILINGS = {
  /** Elements in the whole document, the document element counted. */
  maxElements: 4096,
  /** Levels of nesting from the document element down. */
  maxDepth: 64,
  /** Attributes and namespace declarations on one element, counted together. */
  maxAttributesPerElement: 64,
  /** Characters in one text node. */
  maxTextCharacters: 16384,
  /** Characters in one element or attribute name, its prefix included. */
  maxNameCharacters: 256,
  /** Characters in one attribute value. */
  maxAttributeCharacters: 4096,
  /** Bytes of the canonical form this reader hands back. */
  maxCanonicalBytes: 131072,
} as const;

/** The namespace XML reserves for the attributes prefixed `xml`. */
const XML_NAMESPACE = 'http://www.w3.org/XML/1998/namespace';

export interface XmlAttribute {
  readonly prefix: string;
  readonly localName: string;
  /** The namespace the prefix binds to: the empty string for a name no prefix, since those take none. */
  readonly namespace: string;
  /** The value as the document normalized it, references replaced and line ends settled. */
  readonly value: string;
}

export interface XmlText {
  readonly kind: 'text';
  readonly characters: string;
}

export interface XmlComment {
  readonly kind: 'comment';
  readonly characters: string;
}

export interface XmlInstruction {
  readonly kind: 'instruction';
  readonly target: string;
  readonly data: string;
}

export type XmlNode = XmlElement | XmlText | XmlComment | XmlInstruction;

export interface XmlElement {
  readonly kind: 'element';
  /** The name as the document spelled it, prefix and colon included. */
  readonly name: string;
  readonly prefix: string;
  readonly localName: string;
  /** The namespace the element's own prefix binds to, or the empty string where it carries no prefix. */
  readonly namespace: string;
  readonly attributes: readonly XmlAttribute[];
  readonly children: readonly XmlNode[];
  /** The declarations in scope here by prefix, the default namespace under the empty prefix and `xml` under that one. */
  readonly inScope: ReadonlyMap<string, string>;
  readonly parent: XmlElement | null;
}

export interface XmlDocument {
  readonly root: XmlElement;
  /** The instructions and comments before the document element, and the ones after it, in document order. */
  readonly before: readonly (XmlComment | XmlInstruction)[];
  readonly after: readonly (XmlComment | XmlInstruction)[];
}

export type ReadOutcome = { readonly document: XmlDocument } | { readonly why: string };
export type CanonicalOutcome = { readonly bytes: Uint8Array } | { readonly why: string };

const NAME_START = /^[A-Za-z_:]/u;
const NAME_CHAR = /^[A-Za-z0-9._:-]/u;
const REFERENCE_NAME = /^[A-Za-z0-9._-]/u;
const ABSOLUTE = /^[A-Za-z][A-Za-z0-9+.-]*:/u;
const DIGIT = /^[0-9]$/u;
const HEX_DIGIT = /^[0-9a-fA-F]$/u;
const PREDEFINED: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

/** A cursor over the text, so each production is a step forward or a refusal. */
class Cursor {
  readonly text: string;
  at = 0;

  constructor(text: string) {
    this.text = text;
  }

  get end(): boolean {
    return this.at >= this.text.length;
  }

  peek(): string {
    return this.at < this.text.length ? (this.text[this.at] as string) : '';
  }

  starts(lead: string): boolean {
    return this.text.startsWith(lead, this.at);
  }

  take(count: number): string {
    const taken = this.text.slice(this.at, this.at + count);
    this.at += taken.length;
    return taken;
  }

  skipSpace(): number {
    const before = this.at;
    while (this.at < this.text.length && ' \t\n'.includes(this.text[this.at] as string)) {
      this.at += 1;
    }
    return this.at - before;
  }

  while(pattern: RegExp): string {
    let out = '';
    for (;;) {
      const one = this.peek();
      if (one === '' || !pattern.test(one)) {
        return out;
      }
      out += this.take(1);
    }
  }
}

/** A name as the document spelled it, split into the prefix and the local name a namespace is read from. */
interface SpelledName {
  readonly name: string;
  readonly prefix: string;
  readonly localName: string;
}

/** An attribute or a namespace declaration, read from a start tag before either is bound. */
interface StartTagItem {
  readonly spelled: SpelledName;
  readonly value: string;
  readonly declaration: string | null;
}

class Document {
  private readonly source: Cursor;
  private elements = 0;

  constructor(source: Cursor) {
    this.source = source;
  }

  /** The document element, with the instructions and comments the prolog and the epilog carried. */
  read(): ReadOutcome {
    const before: (XmlComment | XmlInstruction)[] = [];
    const after: (XmlComment | XmlInstruction)[] = [];
    if (this.source.starts('<?xml')) {
      const declared = this.readDeclaration();
      if ('why' in declared) {
        return declared;
      }
    }
    for (;;) {
      const spaced = this.source.skipSpace();
      const outside = this.readOutside();
      if ('why' in outside) {
        return outside;
      }
      if (outside.node === null) {
        if (this.source.end) {
          return { why: 'the document carries no document element' };
        }
        if (spaced === 0 && !this.source.starts('<')) {
          return { why: 'the prolog carries text before the document element' };
        }
        break;
      }
      before.push(outside.node);
    }
    if (!this.source.starts('<')) {
      return { why: 'the document carries no document element' };
    }
    const root = this.readElement(null, 1);
    if ('why' in root) {
      return root;
    }
    for (;;) {
      const spaced = this.source.skipSpace();
      if (this.source.peek() === '') {
        break;
      }
      if (spaced === 0 && !this.source.starts('<')) {
        return { why: 'the document carries content after the document element' };
      }
      const outside = this.readOutside();
      if ('why' in outside) {
        return outside;
      }
      if (outside.node === null) {
        return { why: 'the document carries a second document element' };
      }
      after.push(outside.node);
    }
    return { document: { root: root.element, before, after } };
  }

  /** The `<?xml ... ?>` declaration, which the canonical form drops and this path still reads for its version. */
  private readDeclaration(): { readonly ok: true } | { readonly why: string } {
    this.source.take(5);
    const members: Record<string, string> = {};
    for (;;) {
      this.source.skipSpace();
      if (this.source.starts('?>')) {
        this.source.take(2);
        break;
      }
      if (this.source.end) {
        return { why: 'the XML declaration is not closed' };
      }
      const name = this.readName('the XML declaration');
      if ('why' in name) {
        return name;
      }
      if (!this.source.starts('=')) {
        return { why: `the XML declaration carries no value for ${name.name}` };
      }
      this.source.take(1);
      const value = this.readQuoted();
      if ('why' in value) {
        return value;
      }
      members[name.name] = value.value;
    }
    for (const member of Object.keys(members)) {
      if (!['version', 'encoding', 'standalone'].includes(member)) {
        return { why: `the XML declaration carries the member ${member}, which version 1.0 states nowhere` };
      }
    }
    const stated = members['version'];
    if (stated === undefined) {
      return { why: 'the XML declaration states no version' };
    }
    if (stated !== '1.0') {
      return { why: `the XML declaration states version ${stated} and this path reads 1.0` };
    }
    const encoding = members['encoding'];
    if (encoding !== undefined && encoding.toLowerCase() !== 'utf-8') {
      return { why: `the XML declaration states the encoding ${encoding} and this path reads UTF-8 alone` };
    }
    const standalone = members['standalone'];
    if (standalone !== undefined && standalone !== 'yes' && standalone !== 'no') {
      return { why: `the XML declaration states standalone ${standalone}, which is not one of the two answers version 1.0 allows` };
    }
    return { ok: true };
  }

  /** A comment or an instruction, or null where the next thing to read is not one of them. */
  private readOutside(): { readonly node: XmlComment | XmlInstruction | null } | { readonly why: string } {
    if (this.source.starts('<!--')) {
      return this.readComment();
    }
    if (this.source.starts('<!')) {
      return { why: 'the document carries a document type declaration or an entity declaration, which this path refuses before reading any further' };
    }
    if (this.source.starts('<?')) {
      return this.readInstruction();
    }
    return { node: null };
  }

  private readComment(): { readonly node: XmlComment | null } | { readonly why: string } {
    this.source.take(4);
    const body = this.readUntil('-->');
    if (body === null) {
      return { why: 'a comment is not closed' };
    }
    if (body.includes('--')) {
      return { why: 'a comment carries the two hyphens that would close it' };
    }
    return { node: { kind: 'comment', characters: body } };
  }

  private readInstruction(): { readonly node: XmlInstruction | null } | { readonly why: string } {
    this.source.take(2);
    const target = this.readName('an instruction');
    if ('why' in target) {
      return target;
    }
    if (target.name.toLowerCase() === 'xml') {
      return { why: 'an instruction cannot take the reserved target xml' };
    }
    this.source.skipSpace();
    const data = this.readUntil('?>');
    if (data === null) {
      return { why: `the instruction targeting ${target.name} is not closed` };
    }
    return { node: { kind: 'instruction', target: target.name, data } };
  }

  private readUntil(stop: string): string | null {
    let out = '';
    for (;;) {
      if (this.source.end) {
        return null;
      }
      if (this.source.starts(stop)) {
        this.source.take(stop.length);
        return out;
      }
      out += this.source.take(1);
    }
  }

  /**
   * One element: its start tag read through its declarations, its content read to its end tag.
   *
   * The element object is built before its content is read, because a child carries its parent as the position
   * an omitted-ancestor rule is read from and a namespace is bound from the declarations that precede it. The
   * arrays it holds are filled here and handed out as read-only, which is what lets a subtree know the ancestry
   * it was canonicalized without.
   */
  private readElement(parent: XmlElement | null, depth: number): { readonly element: XmlElement } | { readonly why: string } {
    this.elements += 1;
    if (this.elements > XML_CEILINGS.maxElements) {
      return { why: `the document holds more than the ${String(XML_CEILINGS.maxElements)} elements this path reads` };
    }
    if (depth > XML_CEILINGS.maxDepth) {
      return { why: `the document nests deeper than the ${String(XML_CEILINGS.maxDepth)} levels this path reads` };
    }
    this.source.take(1);
    const name = this.readName('an element');
    if ('why' in name) {
      return name;
    }
    const scope = new Map<string, string>(parent?.inScope ?? [['xml', XML_NAMESPACE]]);
    const items: StartTagItem[] = [];
    const spelled = new Set<string>();
    for (;;) {
      const spaced = this.source.skipSpace();
      if (this.source.starts('/>')) {
        this.source.take(2);
        return this.build(name, scope, items, parent, []);
      }
      if (this.source.starts('>')) {
        this.source.take(1);
        break;
      }
      if (this.source.end) {
        return { why: `the start tag of ${name.name} is not closed` };
      }
      if (spaced === 0) {
        return { why: `the start tag of ${name.name} carries no space before another name` };
      }
      const item = this.readStartTagItem(name.name);
      if ('why' in item) {
        return item;
      }
      if (spelled.has(item.item.spelled.name)) {
        return { why: `the name ${item.item.spelled.name} is written twice on ${name.name}` };
      }
      spelled.add(item.item.spelled.name);
      items.push(item.item);
      if (items.length > XML_CEILINGS.maxAttributesPerElement) {
        return { why: `one element carries more than the ${String(XML_CEILINGS.maxAttributesPerElement)} attributes this path reads` };
      }
    }
    const children: XmlNode[] = [];
    const self = this.build(name, scope, items, parent, children);
    if ('why' in self) {
      return self;
    }
    for (;;) {
      const content = this.readContent(self.element, depth + 1, children);
      if ('why' in content) {
        return content;
      }
      if (content.closed) {
        break;
      }
    }
    return this.readEndTag(name, self.element);
  }

  /** Bind the declarations a start tag carried, then the names of its attributes, then hand the element over. */
  private build(
    name: SpelledName,
    scope: Map<string, string>,
    items: readonly StartTagItem[],
    parent: XmlElement | null,
    children: XmlNode[],
  ): { readonly element: XmlElement } | { readonly why: string } {
    const attributes: XmlAttribute[] = [];
    for (const item of items) {
      if (item.declaration !== null) {
        const bound = bindDeclaration(item.spelled.name, item.value, scope);
        if ('why' in bound) {
          return bound;
        }
        continue;
      }
      const namespace = item.spelled.prefix === '' ? '' : scope.get(item.spelled.prefix);
      if (namespace === undefined) {
        return { why: `the attribute ${item.spelled.name} uses the undeclared prefix ${item.spelled.prefix}` };
      }
      attributes.push({ prefix: item.spelled.prefix, localName: item.spelled.localName, namespace, value: item.value });
    }
    const namespace = name.prefix === '' ? (scope.get('') ?? '') : scope.get(name.prefix);
    if (namespace === undefined) {
      return { why: `the element ${name.name} uses the undeclared prefix ${name.prefix}` };
    }
    return {
      element: {
        kind: 'element',
        name: name.name,
        prefix: name.prefix,
        localName: name.localName,
        namespace,
        attributes,
        children,
        inScope: scope,
        parent,
      },
    };
  }

  private readEndTag(name: SpelledName, element: XmlElement): { readonly element: XmlElement } | { readonly why: string } {
    this.source.take(2);
    const closing = this.readName('an end tag');
    if ('why' in closing) {
      return closing;
    }
    if (closing.name !== name.name) {
      return { why: `the element ${name.name} is closed by ${closing.name}` };
    }
    this.source.skipSpace();
    if (!this.source.starts('>')) {
      return { why: `the end tag of ${name.name} is not closed` };
    }
    this.source.take(1);
    return { element };
  }

  /** One production of content, pushed onto the parent's children, or the mark that the end tag has begun. */
  private readContent(parent: XmlElement, depth: number, into: XmlNode[]): { readonly closed: boolean } | { readonly why: string } {
    if (this.source.starts('</')) {
      return { closed: true };
    }
    if (this.source.starts('<![CDATA[')) {
      this.source.take(9);
      const body = this.readUntil(']]>');
      if (body === null) {
        return { why: 'a CDATA section is not closed' };
      }
      return this.pushText(body, into);
    }
    if (this.source.starts('<!--')) {
      const comment = this.readComment();
      if ('why' in comment) {
        return comment;
      }
      into.push(comment.node as XmlComment);
      return { closed: false };
    }
    if (this.source.starts('<!')) {
      return { why: 'the content carries a document type declaration or an entity declaration, which this path refuses before reading any further' };
    }
    if (this.source.starts('<?')) {
      const instruction = this.readInstruction();
      if ('why' in instruction) {
        return instruction;
      }
      into.push(instruction.node as XmlInstruction);
      return { closed: false };
    }
    if (this.source.starts('<')) {
      const child = this.readElement(parent, depth);
      if ('why' in child) {
        return child;
      }
      into.push(child.element);
      return { closed: false };
    }
    const text = this.readText();
    if ('why' in text) {
      return text;
    }
    return this.pushText(text.characters, into);
  }

  private pushText(characters: string, into: XmlNode[]): { readonly closed: boolean } | { readonly why: string } {
    if (characters.length === 0) {
      return { closed: false };
    }
    const last = into[into.length - 1];
    const joined = last !== undefined && last.kind === 'text' ? last.characters + characters : characters;
    if (joined.includes(']]>')) {
      return { why: 'the content carries the sequence that closes a section it did not open' };
    }
    if (joined.length > XML_CEILINGS.maxTextCharacters) {
      return { why: `a text node is over the ${String(XML_CEILINGS.maxTextCharacters)} characters this path reads` };
    }
    if (last !== undefined && last.kind === 'text') {
      into[into.length - 1] = { kind: 'text', characters: joined };
      return { closed: false };
    }
    into.push({ kind: 'text', characters });
    return { closed: false };
  }

  private readText(): { readonly characters: string } | { readonly why: string } {
    let out = '';
    for (;;) {
      if (this.source.end) {
        return { why: 'the content runs out before its element is closed' };
      }
      const one = this.source.peek();
      if (one === '<') {
        return { characters: out };
      }
      if (one === '&') {
        const reference = this.readReference();
        if ('why' in reference) {
          return reference;
        }
        out += reference.characters;
        continue;
      }
      out += this.source.take(1);
    }
  }

  /** A character reference or one of the five predefined entities, replaced with what it names. */
  private readReference(): { readonly characters: string } | { readonly why: string } {
    this.source.take(1);
    if (this.source.starts('#')) {
      this.source.take(1);
      const hex = this.source.peek().toLowerCase() === 'x';
      if (hex) {
        this.source.take(1);
      }
      const digits = this.source.while(hex ? HEX_DIGIT : DIGIT);
      if (digits.length === 0) {
        return { why: 'a character reference states no character this path can read' };
      }
      if (this.source.peek() !== ';') {
        return { why: `the character reference to ${digits} is not closed` };
      }
      this.source.take(1);
      const value = Number.parseInt(digits, hex ? 16 : 10);
      if (!legalCharacter(value)) {
        return { why: `the character reference names ${digits}, which is not a character XML allows` };
      }
      return { characters: String.fromCodePoint(value) };
    }
    const name = this.source.while(REFERENCE_NAME);
    if (this.source.peek() !== ';') {
      return { why: `the reference to ${name.length === 0 ? 'an unnamed entity' : name} is not closed` };
    }
    this.source.take(1);
    const character = PREDEFINED[name];
    if (character === undefined) {
      return { why: `the document references the undeclared entity ${name}` };
    }
    return { characters: character };
  }

  private readStartTagItem(owner: string): { readonly item: StartTagItem } | { readonly why: string } {
    const spelled = this.readName(`the attribute of ${owner}`);
    if ('why' in spelled) {
      return spelled;
    }
    if (this.source.peek() !== '=') {
      return { why: `the attribute ${spelled.name} of ${owner} states no value` };
    }
    this.source.take(1);
    const value = this.readQuoted();
    if ('why' in value) {
      return value;
    }
    const declaration = spelled.prefix === 'xmlns'
      ? spelled.localName
      : spelled.prefix === '' && spelled.localName === 'xmlns'
        ? ''
        : null;
    return { item: { spelled, value: value.value, declaration } };
  }

  private readQuoted(): { readonly value: string } | { readonly why: string } {
    const quote = this.source.peek();
    if (quote !== '"' && quote !== "'") {
      return { why: 'an attribute value is not written as quoted text' };
    }
    this.source.take(1);
    let value = '';
    for (;;) {
      if (this.source.end) {
        return { why: 'an attribute value is not closed' };
      }
      const one = this.source.peek();
      if (one === quote) {
        this.source.take(1);
        break;
      }
      if (one === '<') {
        return { why: 'an attribute value carries a bare angle bracket' };
      }
      if (one === '\t' || one === '\n') {
        return { why: 'an attribute value carries literal whitespace, which the readers feeding the canonical form settle differently' };
      }
      if (one === '&') {
        const reference = this.readReference();
        if ('why' in reference) {
          return reference;
        }
        value += reference.characters;
        continue;
      }
      value += this.source.take(1);
    }
    if (value.length > XML_CEILINGS.maxAttributeCharacters) {
      return { why: `an attribute value is over the ${String(XML_CEILINGS.maxAttributeCharacters)} characters this path reads` };
    }
    return { value };
  }

  /** A qualified name: one prefix at most, the ASCII name characters this path reads, and a ceiling on length. */
  private readName(where: string): SpelledName | { readonly why: string } {
    if (!NAME_START.test(this.source.peek())) {
      return { why: `${where} does not begin with a name character this path reads` };
    }
    const name = this.source.while(NAME_CHAR);
    if (name.length > XML_CEILINGS.maxNameCharacters) {
      return { why: `a name is over the ${String(XML_CEILINGS.maxNameCharacters)} characters this path reads` };
    }
    const colon = name.indexOf(':');
    if (colon === 0 || colon === name.length - 1 || (colon >= 0 && name.includes(':', colon + 1))) {
      return { why: `${where} spells the name ${name}, which is not one prefix and one local name` };
    }
    return {
      name,
      prefix: colon < 0 ? '' : name.slice(0, colon),
      localName: colon < 0 ? name : name.slice(colon + 1),
    };
  }
}

/** A namespace declaration applied to the scope, with the reserved prefixes and the relative references refused. */
function bindDeclaration(
  name: string,
  value: string,
  scope: Map<string, string>,
): { readonly ok: true } | { readonly why: string } {
  const prefix = name === 'xmlns' ? '' : name.slice('xmlns:'.length);
  if (prefix === 'xml') {
    return { why: 'the xml prefix is not available for a declaration' };
  }
  if (prefix === 'xmlns') {
    return { why: 'the xmlns prefix is not available for a declaration' };
  }
  if (value.length === 0) {
    if (prefix !== '') {
      return { why: `the declaration of the prefix ${prefix} states no namespace` };
    }
    scope.delete('');
    return { ok: true };
  }
  if (!ABSOLUTE.test(value)) {
    return { why: `the declaration ${name} is not an absolute reference` };
  }
  scope.set(prefix, value);
  return { ok: true };
}

function legalCharacter(value: number): boolean {
  return value === 0x9 || value === 0xa || value === 0xd
    || (value >= 0x20 && value <= 0xd7ff)
    || (value >= 0xe000 && value <= 0xfffd)
    || (value >= 0x10000 && value <= 0x10ffff);
}

/**
 * Reads a document in the subset above.
 *
 * A refusal is one line naming what was met, because the answer this belongs to is the unreadable one rather
 * than a stack a caller cannot print.
 */
export function readXml(text: string): ReadOutcome {
  return new Document(new Cursor(stripByteOrderMark(normalizeLineEnds(text)))).read();
}

function stripByteOrderMark(text: string): string {
  return text.startsWith('\uFEFF') ? text.slice(1) : text;
}

function normalizeLineEnds(text: string): string {
  return text.replace(/\r\n/gu, '\n').replace(/\r/gu, '\n');
}

/** Every element of a document, the document element first, in document order. */
export function collectElements(document: XmlDocument): readonly XmlElement[] {
  const found: XmlElement[] = [];
  const walk = (element: XmlElement): void => {
    found.push(element);
    for (const child of element.children) {
      if (child.kind === 'element') {
        walk(child);
      }
    }
  };
  walk(document.root);
  return found;
}

/** The characters an element holds as its own content, or null where it carries anything but text. */
export function elementText(element: XmlElement): string | null {
  let text = '';
  for (const child of element.children) {
    if (child.kind !== 'text') {
      return null;
    }
    text += child.characters;
  }
  return text;
}

/** The value of an attribute carrying a local name in no namespace, which is how the signature spells its own. */
export function attributeOf(element: XmlElement, localName: string): string | null {
  const found = element.attributes.find((attribute) => attribute.localName === localName && attribute.namespace === '');
  return found === undefined ? null : found.value;
}

/** The child elements carrying a local name in one namespace, in document order. */
export function childElements(element: XmlElement, namespace: string, localName: string): readonly XmlElement[] {
  return element.children.filter((child): child is XmlElement => child.kind === 'element' && child.namespace === namespace && child.localName === localName);
}

interface Sink {
  readonly parts: string[];
  length: number;
  why: string | null;
}

/**
 * Canonical XML 1.1 of a whole document, with one element left out of the node-set where the caller names one.
 *
 * The exclusion is the enveloped transform: a manifest signs the document that carries its own signature, so that
 * `ds:Signature` element and all of its content leave the set, and nothing else does. The declarations the removed
 * element carried leave with it, and the ones the document element still holds stay rendered even once no name
 * uses them, because the rule asks what is in scope rather than what is used.
 */
export function canonicalizeDocument(
  document: XmlDocument,
  excluding: XmlElement | null = null,
  options: { readonly comments?: boolean } = {},
): CanonicalOutcome {
  const sink: Sink = { parts: [], length: 0, why: null };
  for (const one of document.before) {
    renderOutside(sink, one, true, options.comments === true);
  }
  renderElement(sink, document.root, null, options.comments === true, excluding, []);
  for (const one of document.after) {
    renderOutside(sink, one, false, options.comments === true);
  }
  return finish(sink);
}

/**
 * Canonical XML 1.1 of one element with its ancestors left out of the node-set, which is what a signature is
 * taken over: the `ds:SignedInfo` element of a manifest, on its own.
 *
 * Two consequences of the rules land here. Every declaration in scope at the top renders, since no ancestor is in
 * the set to carry it, and a simple inheritable attribute of the XML namespace stated by an omitted ancestor is
 * merged into the top element's attribute axis. An omitted ancestor stating `xml:base` would ask for the fixup
 * this path states no rule for, so such a subtree is refused rather than handed back short by a reference.
 */
export function canonicalizeSubtree(element: XmlElement, options: { readonly comments?: boolean } = {}): CanonicalOutcome {
  const inherited = inheritableOfOmittedAncestors(element);
  if (typeof inherited === 'string') {
    return { why: inherited };
  }
  const sink: Sink = { parts: [], length: 0, why: null };
  renderElement(sink, element, null, options.comments === true, null, inherited);
  return finish(sink);
}

/** The simple inheritable attributes an omitted ancestry states for a subtree top, or the refusal naming why. */
function inheritableOfOmittedAncestors(element: XmlElement): readonly XmlAttribute[] | string {
  const nearest = new Map<string, XmlAttribute>();
  for (let walk = element.parent; walk !== null; walk = walk.parent) {
    for (const attribute of walk.attributes) {
      if (attribute.prefix !== 'xml') {
        continue;
      }
      if (attribute.localName === 'base') {
        return 'a subtree here would need an xml:base fixup this path states no rule for';
      }
      if ((attribute.localName === 'lang' || attribute.localName === 'space') && !nearest.has(attribute.localName)) {
        nearest.set(attribute.localName, attribute);
      }
    }
  }
  if (nearest.size === 0) {
    return [];
  }
  const own = new Set(element.attributes.filter((attribute) => attribute.prefix === 'xml').map((attribute) => attribute.localName));
  const merged: XmlAttribute[] = [];
  for (const [localName, attribute] of nearest) {
    if (!own.has(localName)) {
      merged.push(attribute);
    }
  }
  return merged;
}

function renderOutside(sink: Sink, node: XmlComment | XmlInstruction, beforeRoot: boolean, comments: boolean): void {
  if (node.kind === 'comment' && !comments) {
    return;
  }
  const text = node.kind === 'comment' ? `<!--${node.characters}-->` : instructionText(node);
  emit(sink, beforeRoot ? `${text}\n` : `\n${text}`);
}

function instructionText(node: XmlInstruction): string {
  return node.data.length === 0 ? `<?${node.target}?>` : `<?${node.target} ${node.data}?>`;
}

function renderElement(
  sink: Sink,
  element: XmlElement,
  parentScope: ReadonlyMap<string, string> | null,
  comments: boolean,
  excluding: XmlElement | null,
  inherited: readonly XmlAttribute[],
): void {
  if (excluding !== null && excluding === element) {
    return;
  }
  emit(sink, `<${element.name}`);
  renderDeclarations(sink, element.inScope, parentScope);
  for (const attribute of orderedAttributes(element.attributes, inherited)) {
    const name = attribute.prefix === '' ? attribute.localName : `${attribute.prefix}:${attribute.localName}`;
    emit(sink, ` ${name}="${escapeAttribute(attribute.value)}"`);
  }
  emit(sink, '>');
  for (const child of element.children) {
    if (child.kind === 'text') {
      emit(sink, escapeText(child.characters));
    } else if (child.kind === 'element') {
      renderElement(sink, child, element.inScope, comments, excluding, []);
    } else if (child.kind === 'instruction') {
      emit(sink, instructionText(child));
    } else if (comments) {
      emit(sink, `<!--${child.characters}-->`);
    }
  }
  emit(sink, `</${element.name}>`);
}

/**
 * The namespace axis: the declarations in scope by prefix with the default first, each dropped where an element
 * already rendered carries the same prefix bound to the same value. An element whose default namespace is empty
 * under a parent whose default is not renders the empty declaration, since that reset is the only way the
 * difference between the two survives.
 */
function renderDeclarations(sink: Sink, inScope: ReadonlyMap<string, string>, parentScope: ReadonlyMap<string, string> | null): void {
  if (!inScope.has('') && parentScope !== null && parentScope.has('')) {
    emit(sink, ' xmlns=""');
  }
  for (const prefix of [...inScope.keys()].sort()) {
    const uri = inScope.get(prefix) as string;
    if (prefix === 'xml' && uri === XML_NAMESPACE) {
      continue;
    }
    if (parentScope !== null && parentScope.get(prefix) === uri) {
      continue;
    }
    emit(sink, prefix === '' ? ` xmlns="${uri}"` : ` xmlns:${prefix}="${uri}"`);
  }
}

/** The attribute axis: the element's own and any an omitted ancestry states, ordered by namespace and then name. */
function orderedAttributes(own: readonly XmlAttribute[], inherited: readonly XmlAttribute[]): readonly XmlAttribute[] {
  return [...own, ...inherited].sort(byAttributeKey);
}

function byAttributeKey(one: XmlAttribute, other: XmlAttribute): number {
  if (one.namespace !== other.namespace) {
    return one.namespace < other.namespace ? -1 : 1;
  }
  if (one.localName === other.localName) {
    return 0;
  }
  return one.localName < other.localName ? -1 : 1;
}

function emit(sink: Sink, text: string): void {
  if (sink.why !== null) {
    return;
  }
  sink.parts.push(text);
  sink.length += text.length;
  if (sink.length > XML_CEILINGS.maxCanonicalBytes) {
    sink.why = `the canonical form is over the ${String(XML_CEILINGS.maxCanonicalBytes)} bytes this path reads`;
  }
}

function finish(sink: Sink): CanonicalOutcome {
  if (sink.why !== null) {
    return { why: sink.why };
  }
  const bytes = new TextEncoder().encode(sink.parts.join(''));
  if (bytes.byteLength > XML_CEILINGS.maxCanonicalBytes) {
    return { why: `the canonical form is ${String(bytes.byteLength)} bytes, over the ${String(XML_CEILINGS.maxCanonicalBytes)} this path reads` };
  }
  return { bytes };
}

/**
 * Text as the canonical form carries it: the three markup characters and the carriage return become references,
 * and a tab or a line feed stays the character it is.
 */
function escapeText(text: string): string {
  let out = '';
  for (const one of text) {
    out += one === '&' ? '&amp;' : one === '<' ? '&lt;' : one === '>' ? '&gt;' : one === '\r' ? '&#xD;' : one;
  }
  return out;
}

/**
 * An attribute value as the canonical form carries it, which is a different set again: the closing angle bracket
 * stays as it is, while the quotation mark and each of the three whitespace characters become references.
 */
function escapeAttribute(text: string): string {
  let out = '';
  for (const one of text) {
    out += one === '&'
      ? '&amp;'
      : one === '<'
        ? '&lt;'
        : one === '"'
          ? '&quot;'
          : one === '\t'
            ? '&#x9;'
            : one === '\n'
              ? '&#xA;'
              : one === '\r'
                ? '&#xD;'
                : one;
  }
  return out;
}
