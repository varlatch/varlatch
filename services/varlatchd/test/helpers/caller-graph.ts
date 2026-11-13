// SPDX-License-Identifier: AGPL-3.0-or-later
import { dirname, relative, resolve } from "node:path";
import ts from "typescript";

/**
 * Who can reach a function, by the TypeScript type checker (the 40-operation
 * check of ADR-0054 step 4.9, test/admin-step-up-catalogue.test.ts): a
 * test-time guard against ordinary code shapes, not a security boundary
 * against adversarial code, scoped like the lock-trace checker
 * (test/helpers/lock-trace.ts).
 *
 * One ts.Program over src/ (the package's tsconfig), built once per suite
 * run; the self-tests build edited copies through a CompilerHost that
 * serves in-memory text, reusing the base program's unchanged files.
 *
 * - **References by symbol, not by name.** Every identifier in src/ is
 *   resolved with the checker, aliases followed (getAliasedSymbol): renamed
 *   imports, re-exports, and namespace member access all land on the
 *   declared symbol.
 * - **What a reference does:** a call (or `new`) is attributed to its
 *   enclosing function-like declaration, whose own references are then
 *   followed the same way, exported or not; an anonymous callback belongs to
 *   the function it is written in. A value bound to a name
 *   (`const f = g`, `{ m: g }`, `{ g }`) continues through that name's
 *   symbol. A value passed to a route registration is that route.
 * - **Roots** end a chain: a route registration (`app.get/post/put/patch/
 *   delete/all/use/on(...)`, "METHOD /path"), and the functions the caller
 *   names as roots (host commands, startup, background workers), each with
 *   its class.
 * - **Fail closed:** a reference that escapes as a value into anything
 *   else (an argument, an array, a return value), a module's top level that
 *   is not a root, a registration whose path is not a string literal, a
 *   function nothing references, the depth bound, and a target no root
 *   reaches each yield an entry starting with "??", which no expected list
 *   contains. A cycle is followed once. An
 *   identifier the checker cannot resolve and that bears the name of a
 *   function on a chain is reported the same way.
 */

export type RootClass = "route" | "host-command" | "startup" | "worker";

export interface Graph {
  program: ts.Program;
  checker: ts.TypeChecker;
  srcDir: string;
  /** Resolved symbol (by its key) -> its references (identifiers) in src/. */
  refs: Map<SymbolKey, ts.Identifier[]>;
  /** Identifiers in src/ the checker could not resolve, by text. */
  unresolved: Map<string, ts.Identifier[]>;
}

export interface Reach {
  /** "ROOT via outer > ... > inner", or a fail-closed "?? ..." entry. */
  entries: string[];
  /** The classes of the roots reached: "route" for a registration, the named root's class otherwise. */
  classes: RootClass[];
}

const MAX_DEPTH = 12;

/**
 * A symbol's identity: its first declaration. The checker may hand out
 * several symbol objects for one declaration (an object literal's method,
 * seen through the literal's widened type), which are one function here.
 */
type SymbolKey = ts.Node | ts.Symbol;
const keyOf = (symbol: ts.Symbol): SymbolKey => symbol.declarations?.[0] ?? symbol;
const REGISTRATION_METHODS = new Set(["get", "post", "put", "patch", "delete", "all", "use", "on"]);

/**
 * The program over src/, with `edits` (absolute path -> text, new files
 * included) served from memory.
 */
export function buildGraph(packageDir: string, edits: Record<string, string> = {}, oldProgram?: ts.Program): Graph {
  const configPath = resolve(packageDir, "tsconfig.json");
  const config = ts.readConfigFile(configPath, ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, packageDir);
  const options: ts.CompilerOptions = { ...parsed.options, noEmit: true };
  const host = ts.createCompilerHost(options, true);
  const getSourceFile = host.getSourceFile.bind(host);
  host.getSourceFile = (fileName, language, onError, shouldCreate) =>
    fileName in edits ? ts.createSourceFile(fileName, edits[fileName]!, language, true) : getSourceFile(fileName, language, onError, shouldCreate);
  const fileExists = host.fileExists.bind(host);
  host.fileExists = (fileName) => fileName in edits || fileExists(fileName);
  const readFile = host.readFile.bind(host);
  host.readFile = (fileName) => edits[fileName] ?? readFile(fileName);
  const rootNames = [...new Set([...parsed.fileNames, ...Object.keys(edits)])];
  const program = ts.createProgram({ rootNames, options, host, ...(oldProgram ? { oldProgram } : {}) });
  const checker = program.getTypeChecker();
  const srcDir = resolve(packageDir, "src");
  const refs = new Map<SymbolKey, ts.Identifier[]>();
  const unresolved = new Map<string, ts.Identifier[]>();
  for (const sf of srcFiles(program, srcDir)) {
    const visit = (n: ts.Node) => {
      if (ts.isIdentifier(n)) {
        const symbol = symbolOf(checker, n);
        if (symbol) {
          const key = keyOf(symbol);
          const list = refs.get(key);
          if (list) list.push(n);
          else refs.set(key, [n]);
        } else {
          const list = unresolved.get(n.text);
          if (list) list.push(n);
          else unresolved.set(n.text, [n]);
        }
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return { program, checker, srcDir, refs, unresolved };
}

export function srcFiles(program: ts.Program, srcDir: string): ts.SourceFile[] {
  // Migrations run as SQL text at startup, not as callable code.
  return program.getSourceFiles().filter((sf) => !sf.isDeclarationFile && sf.fileName.startsWith(`${srcDir}/`) && !sf.fileName.startsWith(`${srcDir}/db/migrations/`));
}

/** A symbol with its aliases followed. */
function canonical(checker: ts.TypeChecker, symbol: ts.Symbol): ts.Symbol {
  let s = symbol;
  for (let i = 0; i < 20 && s.flags & ts.SymbolFlags.Alias; i++) s = checker.getAliasedSymbol(s);
  return s;
}

/**
 * The symbol an identifier refers to, aliases followed. A shorthand
 * property refers to its value. A name bound by object destructuring
 * (`const { f } = await import("./m.js")`, `const { f } = obj`) refers to
 * the property it takes, so the binding counts as a reference to it.
 */
function symbolOf(checker: ts.TypeChecker, id: ts.Identifier): ts.Symbol | undefined {
  const p = id.parent;
  if (p && ts.isShorthandPropertyAssignment(p) && p.name === id) {
    const value = checker.getShorthandAssignmentValueSymbol(p);
    return value ? canonical(checker, value) : undefined;
  }
  const taken = destructuredProperty(checker, id);
  if (taken !== undefined) return taken ?? undefined;
  const raw = checker.getSymbolAtLocation(id);
  return raw ? canonical(checker, raw) : undefined;
}

/** For the name of an object-destructuring element: the property it takes (null when unresolved); undefined otherwise. */
function destructuredProperty(checker: ts.TypeChecker, id: ts.Identifier): ts.Symbol | null | undefined {
  const p = id.parent;
  if (!p || !ts.isBindingElement(p) || p.name !== id || !ts.isObjectBindingPattern(p.parent)) return undefined;
  const key = p.propertyName ? (ts.isIdentifier(p.propertyName) || ts.isStringLiteral(p.propertyName) ? p.propertyName.text : null) : id.text;
  if (key === null) return null;
  const property = checker.getTypeAtLocation(p.parent).getProperty(key);
  return property ? canonical(checker, property) : null;
}

/** `app.<method>(...)`: a route or middleware registration. */
export function isRegistration(n: ts.Node): n is ts.CallExpression & { expression: ts.PropertyAccessExpression } {
  return ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && ts.isIdentifier(n.expression.expression) &&
    n.expression.expression.text === "app" && REGISTRATION_METHODS.has(n.expression.name.text);
}

/** "POST /v1/..." for a registration, or null when its path is not a string literal. */
export function registrationLabel(call: ts.CallExpression & { expression: ts.PropertyAccessExpression }): string | null {
  const [path] = call.arguments;
  if (!path || !(ts.isStringLiteral(path) || ts.isNoSubstitutionTemplateLiteral(path))) return null;
  return `${call.expression.name.text.toUpperCase()} ${path.text}`;
}

/** Every registration in src/ whose path is not a string literal, as "file:line". */
export function unlabelledRegistrations(g: Graph): string[] {
  const out: string[] = [];
  for (const sf of srcFiles(g.program, g.srcDir)) {
    const visit = (n: ts.Node) => {
      if (isRegistration(n) && registrationLabel(n) === null) out.push(`${rel(g, sf)}:${line(sf, n)}`);
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return out;
}

const rel = (g: Graph, sf: ts.SourceFile) => relative(g.srcDir, sf.fileName);
const line = (sf: ts.SourceFile, n: ts.Node) => sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;

const FUNCTION_LIKE = (n: ts.Node): n is ts.SignatureDeclaration =>
  ts.isFunctionDeclaration(n) || ts.isMethodDeclaration(n) || ts.isArrowFunction(n) || ts.isFunctionExpression(n) ||
  ts.isConstructorDeclaration(n) || ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n);

/** The name a function-like declaration is bound to, or null for an anonymous callback. */
function bindingName(n: ts.SignatureDeclaration): ts.Node | null {
  if ((ts.isFunctionDeclaration(n) || ts.isMethodDeclaration(n) || ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n)) && n.name) return n.name;
  if (ts.isConstructorDeclaration(n)) return n.parent.name ?? null;
  if ((ts.isArrowFunction(n) || ts.isFunctionExpression(n)) && (ts.isVariableDeclaration(n.parent) || ts.isPropertyAssignment(n.parent)) && n.parent.initializer === n) {
    return n.parent.name;
  }
  return null;
}

type Enclosing =
  | { kind: "route"; label: string }
  | { kind: "function"; symbol: ts.Symbol; label: string }
  | { kind: "module"; label: string }
  | { kind: "error"; label: string };

/** What `node` runs in: the nearest route registration or named function-like declaration. */
function enclosingOf(g: Graph, sf: ts.SourceFile, node: ts.Node): Enclosing {
  let child: ts.Node = node;
  for (let p: ts.Node | undefined = node.parent; p; child = p, p = p.parent) {
    if (isRegistration(p) && child !== p.expression) {
      const label = registrationLabel(p);
      return label ? { kind: "route", label: `${rel(g, sf)} ${label}` } : { kind: "error", label: `?? ${rel(g, sf)}:${line(sf, p)} a registration whose path is not a string literal` };
    }
    if (FUNCTION_LIKE(p)) {
      const name = bindingName(p);
      if (!name) continue; // an anonymous callback: part of the function it is written in
      const raw = g.checker.getSymbolAtLocation(name);
      if (!raw) return { kind: "error", label: `?? ${rel(g, sf)}:${line(sf, p)} a function whose symbol cannot be resolved` };
      return { kind: "function", symbol: canonical(g.checker, raw), label: functionLabel(g, sf, p, name) };
    }
  }
  return { kind: "module", label: `${rel(g, sf)} (top level)` };
}

function functionLabel(g: Graph, sf: ts.SourceFile, fn: ts.Node, name: ts.Node): string {
  const own = ts.isIdentifier(name) || ts.isPrivateIdentifier(name) || ts.isStringLiteral(name) ? name.text : name.getText(sf);
  let owner = "";
  const container = ts.isConstructorDeclaration(fn) ? null : fn.parent && ts.isPropertyAssignment(fn.parent) ? fn.parent.parent : fn.parent;
  if (container && ts.isClassLike(container)) owner = `${container.name?.text ?? "(class)"}.`;
  if (container && ts.isObjectLiteralExpression(container)) {
    const holder = container.parent;
    owner = `${holder && ts.isVariableDeclaration(holder) && ts.isIdentifier(holder.name) ? holder.name.text : "{}"}.`;
  }
  return `${rel(g, sf)} ${owner}${ts.isConstructorDeclaration(fn) ? `${own}.constructor` : own}`;
}

type Use =
  | { kind: "call"; at: ts.Node }
  | { kind: "alias"; symbol: ts.Symbol; label: string }
  | { kind: "route"; label: string }
  | { kind: "ignore" }
  | { kind: "escape"; label: string };

/** What a reference to a function does. */
function useOf(g: Graph, sf: ts.SourceFile, id: ts.Identifier, target: ts.Symbol): Use {
  const p = id.parent;
  // Not a use: a declaration of the target itself, an import or export, a type.
  if ((target.declarations ?? []).some((d) => (d as { name?: ts.Node }).name === id)) return { kind: "ignore" };
  // The name of a declaration bound to another symbol object for the same declaration.
  if ((p as { name?: ts.Node }).name === id && keyOf(target) === p) return { kind: "ignore" };
  if (ts.isImportSpecifier(p) || ts.isImportClause(p) || ts.isNamespaceImport(p) || ts.isExportSpecifier(p) || ts.isImportEqualsDeclaration(p)) {
    return { kind: "ignore" };
  }
  if (ts.isTypeQueryNode(p) || ts.isTypeReferenceNode(p) || (ts.isQualifiedName(p) && p.right === id)) return { kind: "ignore" };
  if (ts.isBindingElement(p) && p.name === id) {
    const local = g.checker.getSymbolAtLocation(id);
    return local ? { kind: "alias", symbol: local, label: `${id.text} (destructured)` } : { kind: "escape", label: escape(g, sf, id, "an unresolved destructured binding") };
  }
  if (ts.isShorthandPropertyAssignment(p) && p.name === id) {
    const prop = g.checker.getSymbolAtLocation(p.name);
    return prop ? { kind: "alias", symbol: canonical(g.checker, prop), label: `${p.name.text} (property)` } : { kind: "escape", label: escape(g, sf, id, "an unresolved shorthand property") };
  }
  let e: ts.Node = ts.isPropertyAccessExpression(p) && p.name === id ? p : id;
  while (e.parent && (ts.isParenthesizedExpression(e.parent) || ts.isAsExpression(e.parent) || ts.isNonNullExpression(e.parent) ||
    ts.isSatisfiesExpression(e.parent) || ts.isTypeAssertionExpression(e.parent))) e = e.parent;
  const q = e.parent;
  if (!q) return { kind: "escape", label: escape(g, sf, id, "no parent") };
  if ((ts.isCallExpression(q) || ts.isNewExpression(q)) && q.expression === e) return { kind: "call", at: q };
  if (ts.isVariableDeclaration(q) && q.initializer === e) {
    const s = ts.isIdentifier(q.name) ? g.checker.getSymbolAtLocation(q.name) : undefined;
    return s ? { kind: "alias", symbol: canonical(g.checker, s), label: `${q.name.getText(sf)} (alias)` } : { kind: "escape", label: escape(g, sf, id, "a destructured binding") };
  }
  if (ts.isPropertyAssignment(q) && q.initializer === e) {
    const s = g.checker.getSymbolAtLocation(q.name);
    return s ? { kind: "alias", symbol: canonical(g.checker, s), label: `${q.name.getText(sf)} (property)` } : { kind: "escape", label: escape(g, sf, id, "an unresolved property") };
  }
  if (isRegistration(q) && q.arguments.some((a) => a === e)) {
    const label = registrationLabel(q);
    return label ? { kind: "route", label: `${rel(g, sf)} ${label}` } : { kind: "escape", label: escape(g, sf, id, "a registration whose path is not a string literal") };
  }
  return { kind: "escape", label: escape(g, sf, id, `a value passed on (${ts.SyntaxKind[q.kind]})`) };
}

const escape = (g: Graph, sf: ts.SourceFile, id: ts.Identifier, what: string) => `?? ${rel(g, sf)}:${line(sf, id)} ${id.text}: ${what}`;

/**
 * Every root that can reach `target` (a function's symbol), through the
 * transitive caller graph. `roots` names the functions that end a chain
 * ("cli.ts adminCommand"), in addition to route registrations.
 */
export function reach(g: Graph, target: ts.Symbol, roots: ReadonlyMap<string, RootClass>): Reach {
  const entries = new Set<string>();
  const reached = new Set<RootClass>();
  const walk = (symbol: ts.Symbol, chain: readonly string[], seen: ReadonlySet<SymbolKey>) => {
    const via = chain.length > 0 ? ` via ${[...chain].reverse().join(" > ")}` : "";
    if (chain.length > MAX_DEPTH) {
      entries.add(`?? depth bound${via}`);
      return;
    }
    // Unresolved identifiers bearing this function's name may be calls the checker could not follow.
    for (const id of g.unresolved.get(symbol.name) ?? []) {
      const sf = id.getSourceFile();
      entries.add(`${escape(g, sf, id, "an identifier the checker cannot resolve")}${via}`);
    }
    const uses = g.refs.get(keyOf(symbol)) ?? [];
    let used = false;
    for (const id of uses) {
      const sf = id.getSourceFile();
      const use = useOf(g, sf, id, symbol);
      if (use.kind === "ignore") continue;
      used = true;
      if (use.kind === "escape") entries.add(`${use.label}${via}`);
      else if (use.kind === "route") {
        entries.add(`${use.label}${via}`);
        reached.add("route");
      } else if (use.kind === "alias") {
        // A cycle reaches no root the other references do not.
        if (!seen.has(keyOf(use.symbol))) walk(use.symbol, [...chain, use.label], new Set([...seen, keyOf(use.symbol)]));
      } else {
        const ctx = enclosingOf(g, sf, use.at);
        if (ctx.kind === "error") entries.add(`${ctx.label}${via}`);
        else if (ctx.kind === "route") {
          entries.add(`${ctx.label}${via}`);
          reached.add("route");
        } else if (ctx.kind === "module") {
          entries.add(`?? ${ctx.label}, not a root${via}`);
        } else if (roots.has(ctx.label)) {
          entries.add(`${ctx.label}${via}`);
          reached.add(roots.get(ctx.label)!);
        } else if (!seen.has(keyOf(ctx.symbol))) {
          walk(ctx.symbol, [...chain, ctx.label.slice(ctx.label.indexOf(" ") + 1)], new Set([...seen, keyOf(ctx.symbol)]));
        }
      }
    }
    if (!used) entries.add(`?? ${symbol.name}: nothing references it${via}`);
  };
  walk(target, [], new Set([keyOf(target)]));
  if (entries.size === 0) entries.add(`?? ${target.name}: no root reaches it`);
  return { entries: [...entries].sort(), classes: [...reached].sort() };
}

/** The label of every named function-like declaration in src/ ("file name"), as roots are named. */
export function functionLabels(g: Graph): Set<string> {
  const out = new Set<string>();
  for (const sf of srcFiles(g.program, g.srcDir)) {
    const visit = (n: ts.Node) => {
      if (FUNCTION_LIKE(n)) {
        const name = bindingName(n);
        if (name) out.add(functionLabel(g, sf, n, name));
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return out;
}

/** The function `name` declared at the top level of `file` (relative to src/), exported or not. */
export function declaredSymbol(g: Graph, file: string, name: string): ts.Symbol {
  const sf = g.program.getSourceFile(resolve(g.srcDir, file));
  if (!sf) throw new Error(`no source ${file}`);
  for (const st of sf.statements) {
    const names = ts.isFunctionDeclaration(st) && st.name ? [st.name]
      : ts.isVariableStatement(st) ? st.declarationList.declarations.map((d) => d.name).filter(ts.isIdentifier) : [];
    const found = names.find((n) => n.text === name);
    const symbol = found && g.checker.getSymbolAtLocation(found);
    if (symbol) return canonical(g.checker, symbol);
  }
  throw new Error(`${file} declares no ${name} at its top level`);
}

/** The exported function `name` of `file` (relative to src/), resolved. */
export function exportedSymbol(g: Graph, file: string, name: string): ts.Symbol {
  const sf = g.program.getSourceFile(resolve(g.srcDir, file));
  if (!sf) throw new Error(`no source ${file}`);
  const moduleSymbol = g.checker.getSymbolAtLocation(sf);
  const symbol = moduleSymbol && g.checker.getExportsOfModule(moduleSymbol).find((s) => s.name === name);
  if (!symbol) throw new Error(`${file} exports no ${name}`);
  return canonical(g.checker, symbol);
}

/**
 * Every string or template literal in src/ that `write` matches, by its
 * enclosing route or function ("file name"), with that function's symbol
 * (null for a route, a root's own body, or a fail-closed entry).
 */
export function writers(g: Graph, write: RegExp): { label: string; symbol: ts.Symbol | null }[] {
  const out = new Map<string, ts.Symbol | null>();
  for (const sf of srcFiles(g.program, g.srcDir)) {
    const visit = (n: ts.Node) => {
      if ((ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n) || ts.isTemplateExpression(n)) && write.test(n.getText(sf))) {
        const ctx = enclosingOf(g, sf, n);
        out.set(ctx.kind === "error" ? ctx.label : ctx.kind === "module" ? `?? ${ctx.label}` : ctx.label, ctx.kind === "function" ? ctx.symbol : null);
        return;
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return [...out].map(([label, symbol]) => ({ label, symbol })).sort((a, b) => (a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
}

/** The absolute path of a file under src/. */
export const srcPath = (g: Pick<Graph, "srcDir">, file: string) => resolve(g.srcDir, file);
export const packageDirOf = (testFileUrl: string) => resolve(dirname(new URL(testFileUrl).pathname), "..");
