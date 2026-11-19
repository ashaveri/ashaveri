import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const WORKSPACE = fileURLToPath(new URL('../../../', import.meta.url));

function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return /\.(?:cts|mts|tsx|ts)$/u.test(entry.name) ? [path] : [];
  });
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function config(directory: string): ts.ParsedCommandLine {
  const path = join(directory, 'tsconfig.json');
  const read = ts.readConfigFile(path, ts.sys.readFile);
  if (read.error) throw new Error(`cannot read ${relative(WORKSPACE, path)}`);
  const parsed = ts.parseJsonConfigFileContent(read.config, ts.sys, directory);
  if (parsed.errors.length) throw new Error(`unsupported compiler metadata in ${relative(WORKSPACE, path)}`);
  return parsed;
}

// Export targets and compiler output directories, not package names, determine source entry points.
function workspaceExports(directories: readonly string[]): Map<string, Map<string, string>> {
  const packages = new Map<string, Map<string, string>>();
  for (const directory of directories) {
    const metadata: unknown = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'));
    if (!object(metadata) || typeof metadata.name !== 'string') throw new Error('workspace package lacks a name');
    if (packages.has(metadata.name)) throw new Error(`duplicate workspace package ${metadata.name}`);
    const entries = new Map<string, string>();
    packages.set(metadata.name, entries);
    if (metadata.exports === undefined) continue;
    if (!object(metadata.exports)) throw new Error(`unsupported exports for ${metadata.name}`);
    const { rootDir, outDir, declarationDir } = config(directory).options;
    if (!rootDir || !outDir) throw new Error(`missing source/output directories for ${metadata.name}`);
    for (const [subpath, target] of Object.entries(metadata.exports)) {
      if (subpath !== '.' && !/^\.\/[^*]+$/u.test(subpath)) {
        throw new Error(`unsupported export ${metadata.name} ${subpath}`);
      }
      if (!object(target) || typeof target.types !== 'string' || !target.types.startsWith('./')) {
        throw new Error(`unsupported type export ${metadata.name} ${subpath}`);
      }
      const output = relative(declarationDir ?? outDir, resolve(directory, target.types));
      if (output.startsWith('..') || isAbsolute(output) || !/\.d\.(?:cts|mts|ts)$/u.test(output)) {
        throw new Error(`type export outside compiler output for ${metadata.name} ${subpath}`);
      }
      const source = join(rootDir, output.replace(/\.d\.(cts|mts|ts)$/u, '.$1'));
      const candidates = [source, ...(source.endsWith('.ts') ? [source.slice(0, -3) + '.tsx'] : [])]
        .filter((path) => existsSync(path));
      if (candidates.length !== 1) throw new Error(`unresolved source export for ${metadata.name} ${subpath}`);
      entries.set(subpath === '.' ? metadata.name : metadata.name + subpath.slice(1), candidates[0]!);
    }
  }
  return packages;
}

function programFor(files: string[], directories: string[]): ts.Program {
  const packages = workspaceExports(directories.filter((directory) => existsSync(join(directory, 'package.json'))));
  const options: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2023,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    strict: true,
    skipLibCheck: true,
    noEmit: true,
  };
  const host = ts.createCompilerHost(options);
  host.resolveModuleNames = (names, containingFile) => names.map((name) => {
    const owner = [...packages.keys()].find((pkg) => name === pkg || name.startsWith(`${pkg}/`));
    if (owner) {
      const source = packages.get(owner)!.get(name);
      if (!source) throw new Error(`unsupported workspace import ${name}`);
      return { resolvedFileName: source, isExternalLibraryImport: false };
    }
    return ts.resolveModuleName(name, containingFile, options, host).resolvedModule;
  });
  return ts.createProgram(files, options, host);
}

function unparenthesized(node: ts.TypeNode): ts.TypeNode {
  return ts.isParenthesizedTypeNode(node) ? unparenthesized(node.type) : node;
}

function definingFamily(checker: ts.TypeChecker, annotation: ts.TypeNode): ts.TypeAliasDeclaration {
  let node = unparenthesized(annotation);
  const seen = new Set<ts.Symbol>();
  while (ts.isTypeReferenceNode(node) && !node.typeArguments?.length) {
    let symbol = checker.getSymbolAtLocation(node.typeName);
    if (symbol && (symbol.flags & ts.SymbolFlags.Alias)) symbol = checker.getAliasedSymbol(symbol);
    if (!symbol || seen.has(symbol)) throw new Error('unresolved or cyclic code-family alias');
    seen.add(symbol);
    const declarations = symbol.declarations ?? [];
    const declaration = declarations[0];
    if (declarations.length !== 1 || !declaration || !ts.isTypeAliasDeclaration(declaration) || declaration.typeParameters?.length) {
      throw new Error('code needs one unambiguous named non-generic family');
    }
    node = unparenthesized(declaration.type);
    if (!ts.isTypeReferenceNode(node)) return declaration;
  }
  throw new Error('code needs a named family annotation, not an unnamed or ambiguous type');
}

function stringMembers(checker: ts.TypeChecker, node: ts.TypeNode): string[] {
  const plain = unparenthesized(node);
  if (ts.isUnionTypeNode(plain)) return [...new Set(plain.types.flatMap((part) => stringMembers(checker, part)))];
  const type = checker.getTypeFromTypeNode(plain);
  const members = type.isUnion() ? type.types : [type];
  return members.map((member) => {
    if (!member.isStringLiteral()) throw new Error(`unsupported code member ${checker.typeToString(member)}; expected finite string literals`);
    return member.value;
  });
}

function derivesFromError(program: ts.Program, checker: ts.TypeChecker, type: ts.Type, seen = new Set<ts.Type>()): boolean {
  if (seen.has(type)) return false;
  seen.add(type);
  if (type.getSymbol()?.declarations?.some((declaration) =>
    ts.isInterfaceDeclaration(declaration) && declaration.name.text === 'Error' &&
    program.isSourceFileDefaultLibrary(declaration.getSourceFile()))) return true;
  if (!(type.flags & ts.TypeFlags.Object)) return false;
  const objectType = type as ts.ObjectType;
  if (objectType.objectFlags & ts.ObjectFlags.Reference) {
    const target = (objectType as ts.TypeReference).target;
    if (target !== type) return derivesFromError(program, checker, target, seen);
  }
  if (!(objectType.objectFlags & ts.ObjectFlags.ClassOrInterface)) return false;
  for (const declaration of type.getSymbol()?.declarations ?? []) {
    if (!ts.isClassDeclaration(declaration) && !ts.isClassExpression(declaration)) continue;
    for (const clause of declaration.heritageClauses ?? []) {
      if (clause.token !== ts.SyntaxKind.ExtendsKeyword) continue;
      for (const base of clause.types) {
        const constructor = checker.getTypeAtLocation(base.expression);
        if (constructor.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown | ts.TypeFlags.Never)) {
          throw new Error('unsupported or unresolved base class; cannot establish standard Error ancestry');
        }
      }
    }
  }
  return checker.getBaseTypes(objectType as ts.InterfaceType).some((base) => derivesFromError(program, checker, base, seen));
}

// Re-enumeration is intentional: an untracked source must participate without a restart or a build.
export function discoverCodeFamilies(): Map<string, string[]> {
  const directories = [
    join(WORKSPACE, 'gateway'),
    ...readdirSync(join(WORKSPACE, 'packages'), { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => join(WORKSPACE, 'packages', entry.name)),
  ].filter((directory) => existsSync(join(directory, 'src')));
  const files = directories.flatMap((directory) => sourceFiles(join(directory, 'src'))).sort();
  const program = programFor(files, directories);
  const checker = program.getTypeChecker();
  const found = new Map<string, { declaration: ts.TypeAliasDeclaration; codes: string[] }>();
  const problems: string[] = [];
  for (const path of files) {
    const source = program.getSourceFile(path);
    if (!source) throw new Error(`source not loaded: ${relative(WORKSPACE, path)}`);
    for (const diagnostic of program.getSyntacticDiagnostics(source)) {
      problems.push(`${relative(WORKSPACE, path)}: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, ' ')}`);
    }
    const visit = (node: ts.Node): void => {
      if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
        const instance = checker.getDeclaredTypeOfSymbol(checker.getTypeAtLocation(node).getSymbol()!);
        const code = instance.getProperty('code');
        if (code) {
          try {
            if (!derivesFromError(program, checker, instance)) {
              ts.forEachChild(node, visit);
              return;
            }
            const annotations = (code.declarations ?? []).flatMap((declaration) =>
              (ts.isPropertyDeclaration(declaration) || ts.isParameter(declaration) || ts.isGetAccessorDeclaration(declaration)) && declaration.type
                ? [declaration.type] : []);
            if (annotations.length !== 1) throw new Error('code needs one named family annotation');
            const declaration = definingFamily(checker, annotations[0]!);
            const codes = stringMembers(checker, declaration.type);
            const actual = checker.getTypeOfSymbolAtLocation(code, node);
            if ((actual.isUnion() ? actual.types : [actual]).some((member) => !member.isStringLiteral())) {
              throw new Error(`unsupported instance code type ${checker.typeToString(actual)}`);
            }
            const name = declaration.name.text;
            const previous = found.get(name);
            if (previous && previous.declaration !== declaration) throw new Error(`duplicate documentation name ${name}`);
            found.set(name, { declaration, codes });
          } catch (error) {
            if (!(error instanceof Error)) throw error;
            const { line } = source.getLineAndCharacterOfPosition(node.getStart());
            problems.push(`${relative(WORKSPACE, path)}:${line + 1} ${node.name?.text ?? '<class>'}.code: ${error.message}`);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  if (problems.length) throw new Error(problems.join('\n'));
  return new Map([...found].map(([name, family]) => [name, family.codes]));
}
