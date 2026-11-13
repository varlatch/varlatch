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
 *   declared symbol. An element access with a literal key
 *   (`handlers["mint"]`, `ns["f"]`) is resolved like the property access it
 *   spells.
 * - **Holders fail closed when they escape.** A holder is an object whose
 *   type has, directly or nested, a property that is a function declared in
 *   src/ (a method, or a property holding a function). A reference to a
 *   holder (an identifier, `this`, a property or element access) may only
 *   be the receiver of a resolvable member access (`h.mint`, `h["mint"]`),
 *   the initializer of a variable (`const x = h`, `const { mint } = h`),
 *   whose own references are held to the same rule, or a type position.
 *   Anywhere else (an argument, to `Object.values` or any other function, a
 *   spread, a return value, a store, a computed key `h[name]`) it is
 *   recorded, and a function on a chain among its properties yields a "??"
 *   entry naming the holder. The rule looks at every expression that may
 *   evaluate to an object (a call result, `new`, `await`, an inline literal,
 *   a conditional), sees through unions, intersections and Promises, counts a
 *   module namespace's members (`import * as ns`, `await import()`), and a
 *   destructuring with a computed key (`const { [k]: f } = h`) is an escape.
 * - **Dispatch through a member without a body fails closed.** A use of an
 *   interface, type-literal or abstract member (`(h as Minter).mint()`,
 *   `m: Base; m.mint()`) may run any implementation; when a function on a
 *   chain is a member with that name, the use yields a "??" entry.
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
 * - **Only `app` registers routes.** A registration method (or `route`,
 *   `mount`, `basePath`) called on any other Hono router, by its type (a
 *   variable of another name, a chained `app.get(...).post(...)`, a
 *   sub-router), fails closed: its path would not be the route's full path,
 *   and a callback passed to it would otherwise be attributed to the
 *   function it is written in. `otherRouterCalls` lists every such call.
 * - **Writers by SQL text.** `writers` reads each SQL expression as one
 *   text: a string or template literal, or a `+` concatenation of them, with
 *   every part that is not a literal (a template substitution, a variable)
 *   as a hole. A write (`INSERT INTO`, `UPDATE`, `DELETE FROM`) whose table
 *   is a hole, or that ends the text with nothing after it, fails closed:
 *   the table it writes cannot be read from the source.
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
  /** Resolved symbol (by its key) -> its references in src/: identifiers, and the literal keys of element accesses. */
  refs: Map<SymbolKey, RefNode[]>;
  /** References in src/ the checker could not resolve, by text. */
  unresolved: Map<string, RefNode[]>;
  /**
   * Holder references outside the allowed positions (see the top of this
   * file): each with the keys of the functions its type holds, directly or
   * nested.
   */
  dynamic: { node: ts.Node; what: string; keys: Set<SymbolKey> }[];
  /**
   * Uses of members without a body (an interface, type-literal or abstract
   * member, or a function-typed property signature), by name: a call
   * through one may dispatch to any implementation with that name.
   */
  bodiless: Map<string, { ref: RefNode; owner: string }[]>;
}

/** A reference: an identifier, or the string-literal key of an element access (`handlers["mint"]`). */
type RefNode = ts.Identifier | ts.StringLiteral | ts.NoSubstitutionTemplateLiteral;

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
/** Router methods that mount or derive another router: on `app` or any other router, they fail closed. */
const ROUTER_METHODS = new Set([...REGISTRATION_METHODS, "route", "mount", "basePath"]);

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
  const refs = new Map<SymbolKey, RefNode[]>();
  const unresolved = new Map<string, RefNode[]>();
  const dynamic: Graph["dynamic"] = [];
  const add = (ref: RefNode, symbol: ts.Symbol | undefined) => {
    const map = symbol ? refs : unresolved;
    const key = symbol ? keyOf(symbol) : ref.text;
    const list = (map as Map<SymbolKey | string, RefNode[]>).get(key);
    if (list) list.push(ref);
    else (map as Map<SymbolKey | string, RefNode[]>).set(key, [ref]);
  };
  const srcPrefix = `${srcDir}/`;
  const inSrc = (d: ts.Node) => d.getSourceFile().fileName.startsWith(srcPrefix);
  // A property that can carry a function: a method, an object property or class field, an accessor, and a
  // module namespace's member (a function declaration, an exported variable).
  const CARRIER = (d: ts.Node) => ts.isMethodDeclaration(d) || ts.isPropertyAssignment(d) || ts.isShorthandPropertyAssignment(d) ||
    ts.isPropertyDeclaration(d) || ts.isGetAccessorDeclaration(d) || ts.isFunctionDeclaration(d) || ts.isVariableDeclaration(d);
  const memo = new Map<ts.Type, Set<SymbolKey>>();
  const NONE = new Set<SymbolKey>();
  /**
   * The keys of the functions a type holds as properties, directly or
   * nested: through each member of a union or intersection
   * (`Handlers | undefined`), and through what a Promise resolves to
   * (memoized per type, cycles cut).
   */
  const heldKeys = (type: ts.Type, depth = 0): Set<SymbolKey> => {
    const known = memo.get(type);
    if (known) return known;
    if (depth > 4) return NONE;
    const keys = new Set<SymbolKey>();
    memo.set(type, keys);
    if (type.isUnionOrIntersection()) {
      for (const t of type.types) for (const k of heldKeys(t, depth + 1)) keys.add(k);
      return keys;
    }
    if (!(type.flags & ts.TypeFlags.Object)) return keys;
    const awaited = checker.getAwaitedType(type);
    if (awaited && awaited !== type) for (const k of heldKeys(awaited, depth + 1)) keys.add(k);
    for (const prop of checker.getPropertiesOfType(type)) {
      const symbol = canonical(checker, prop);
      const decl = symbol.declarations?.[0];
      if (!decl || !inSrc(decl)) continue;
      const propType = checker.getTypeOfSymbolAtLocation(prop, decl);
      // Only a property whose value is callable can be a function on a chain.
      if (CARRIER(decl) && propType.getCallSignatures().length > 0) keys.add(keyOf(symbol));
      // A property holding a function declared elsewhere (`{ mint: issueCredential }`, `{ issueCredential }`).
      const value = prop.valueDeclaration;
      const held = value && ts.isPropertyAssignment(value) && ts.isIdentifier(value.initializer) ? checker.getSymbolAtLocation(value.initializer)
        : value && ts.isShorthandPropertyAssignment(value) ? checker.getShorthandAssignmentValueSymbol(value) : undefined;
      if (held) keys.add(keyOf(canonical(checker, held)));
      for (const k of heldKeys(propType, depth + 1)) keys.add(k);
    }
    return keys;
  };
  /** Whether an identifier is a value reference, not a name, a key or part of a type. */
  const isValueReference = (id: ts.Identifier): boolean => {
    const p = id.parent;
    if (ts.isShorthandPropertyAssignment(p)) return true; // `{ h }` stores h
    if ((p as { name?: ts.Node }).name === id || (p as { propertyName?: ts.Node }).propertyName === id) return false;
    if (ts.isTypeNode(p) || ts.isQualifiedName(p) || ts.isImportSpecifier(p) || ts.isExportSpecifier(p) || ts.isImportClause(p) ||
      ts.isNamespaceImport(p) || ts.isImportEqualsDeclaration(p) || ts.isLabeledStatement(p) || ts.isBreakOrContinueStatement(p)) return false;
    return true;
  };
  const isLiteralKey = (k: ts.Node) => ts.isStringLiteral(k) || ts.isNoSubstitutionTemplateLiteral(k);
  /** A binding pattern with a computed, non-literal key anywhere (`const { [k]: f } = h`). */
  const computedKeyIn = (name: ts.BindingName): boolean =>
    !ts.isIdentifier(name) && name.elements.some((el) => ts.isBindingElement(el) &&
      ((el.propertyName && ts.isComputedPropertyName(el.propertyName) && !isLiteralKey(el.propertyName.expression)) || computedKeyIn(el.name)));
  /** Null when a holder reference is in an allowed position; otherwise what it does there. */
  const escapeOf = (e: ts.Node, sf: ts.SourceFile): string | null => {
    let x: ts.Node = e;
    while (x.parent && (ts.isParenthesizedExpression(x.parent) || ts.isAsExpression(x.parent) || ts.isNonNullExpression(x.parent) ||
      ts.isSatisfiesExpression(x.parent) || ts.isTypeAssertionExpression(x.parent) || ts.isAwaitExpression(x.parent))) x = x.parent;
    const p = x.parent;
    if (!p) return "no parent";
    if (ts.isPropertyAccessExpression(p) && p.expression === x) return null;
    if (ts.isElementAccessExpression(p) && p.expression === x) {
      return isLiteralKey(p.argumentExpression) ? null : `a computed access ${p.getText(sf)}`;
    }
    if (ts.isVariableDeclaration(p) && p.initializer === x) {
      return computedKeyIn(p.name) ? `a computed destructuring ${p.name.getText(sf)}` : null;
    }
    // An object literal or class expression defining a property is the holder's own definition; anything else stored there is a store.
    if ((ts.isPropertyAssignment(p) || ts.isPropertyDeclaration(p)) && p.initializer === x && (ts.isObjectLiteralExpression(e) || ts.isClassExpression(e))) return null;
    if (ts.isTypeQueryNode(p)) return null;
    return `${e.getText(sf)} passed on (${ts.SyntaxKind[p.kind]})`;
  };
  /** An expression that may evaluate to an object: what the holder rule looks at. */
  const isCandidate = (n: ts.Node): boolean =>
    (ts.isIdentifier(n) && isValueReference(n)) || n.kind === ts.SyntaxKind.ThisKeyword ||
    ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n) || ts.isCallExpression(n) || ts.isNewExpression(n) ||
    ts.isTaggedTemplateExpression(n) || ts.isObjectLiteralExpression(n) || ts.isClassExpression(n) || ts.isConditionalExpression(n) ||
    (ts.isBinaryExpression(n) && [ts.SyntaxKind.QuestionQuestionToken, ts.SyntaxKind.BarBarToken, ts.SyntaxKind.AmpersandAmpersandToken].includes(n.operatorToken.kind));
  /** A member without a body: an interface, type-literal or abstract member, or a property signature. */
  const isBodiless = (d: ts.Node) => ts.isMethodSignature(d) || ts.isPropertySignature(d) ||
    ((ts.isMethodDeclaration(d) || ts.isPropertyDeclaration(d)) && (ts.getCombinedModifierFlags(d) & ts.ModifierFlags.Abstract) !== 0);
  const ownerOf = (d: ts.Node) => {
    const o = d.parent;
    return (o && (ts.isInterfaceDeclaration(o) || ts.isClassLike(o)) && o.name ? o.name.text : "{}");
  };
  const bodiless: Graph["bodiless"] = new Map();
  const noteBodiless = (ref: RefNode, symbol: ts.Symbol | undefined) => {
    const decls = symbol?.declarations ?? [];
    if (decls.length === 0 || !decls.every(isBodiless)) return;
    const name = symbol!.name;
    const list = bodiless.get(name);
    const entry = { ref, owner: `${ownerOf(decls[0]!)}.${name}` };
    if (list) list.push(entry);
    else bodiless.set(name, [entry]);
  };
  for (const sf of srcFiles(program, srcDir)) {
    const visit = (n: ts.Node) => {
      if (ts.isIdentifier(n)) {
        const symbol = symbolOf(checker, n);
        add(n, symbol);
        // A member named by a property access (`m.mint`) is used too, not declared.
        if (isValueReference(n) || (ts.isPropertyAccessExpression(n.parent) && n.parent.name === n)) noteBodiless(n, symbol);
      } else if (ts.isElementAccessExpression(n)) {
        const arg = n.argumentExpression;
        if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) {
          // obj["name"]: the property it names, as obj.name would.
          const raw = checker.getSymbolAtLocation(arg) ?? checker.getTypeAtLocation(n.expression).getProperty(arg.text);
          const symbol = raw ? canonical(checker, raw) : undefined;
          add(arg, symbol);
          noteBodiless(arg, symbol);
        }
      }
      // The holder rule: an expression whose type holds functions, outside the allowed positions.
      if (isCandidate(n)) {
        const what = escapeOf(n, sf);
        if (what !== null) {
          const keys = heldKeys(checker.getTypeAtLocation(n));
          if (keys.size > 0) dynamic.push({ node: n, what, keys });
        }
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return { program, checker, srcDir, refs, unresolved, dynamic, bodiless };
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
  const pn = p.propertyName;
  const key = !pn ? id.text
    : ts.isIdentifier(pn) || ts.isStringLiteral(pn) ? pn.text
    : ts.isComputedPropertyName(pn) && (ts.isStringLiteral(pn.expression) || ts.isNoSubstitutionTemplateLiteral(pn.expression)) ? pn.expression.text
    : null;
  if (key === null) return null;
  const property = checker.getTypeAtLocation(p.parent).getProperty(key);
  return property ? canonical(checker, property) : null;
}

/** `app.<method>(...)`: a route or middleware registration. */
export function isRegistration(n: ts.Node): n is ts.CallExpression & { expression: ts.PropertyAccessExpression } {
  return ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && ts.isIdentifier(n.expression.expression) &&
    n.expression.expression.text === "app" && REGISTRATION_METHODS.has(n.expression.name.text);
}

/** Whether an expression's type is one of Hono's routers (Hono, HonoBase), declared in the hono package. */
function isHonoRouter(checker: ts.TypeChecker, e: ts.Expression): boolean {
  const type = checker.getTypeAtLocation(e);
  const types = type.isUnionOrIntersection() ? type.types : [type];
  return types.some((t) => {
    const symbol = t.getSymbol() ?? t.aliasSymbol;
    return !!symbol && /^Hono/.test(symbol.getName()) &&
      (symbol.declarations ?? []).some((d) => /[\\/]node_modules[\\/]hono[\\/]/.test(d.getSourceFile().fileName));
  });
}

/**
 * A call of a router method on a Hono router that is not an `app`
 * registration: another variable, a chained call, `route`, `mount` or
 * `basePath`. Such a call fails closed (see the top of this file).
 */
function isOtherRouterCall(checker: ts.TypeChecker, n: ts.Node): n is ts.CallExpression & { expression: ts.PropertyAccessExpression } {
  return ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && ROUTER_METHODS.has(n.expression.name.text) &&
    !isRegistration(n) && isHonoRouter(checker, n.expression.expression);
}

/** Every call in src/ of a router method on a Hono router other than an `app` registration, as "file:line". */
export function otherRouterCalls(g: Graph): string[] {
  const out: string[] = [];
  for (const sf of srcFiles(g.program, g.srcDir)) {
    const visit = (n: ts.Node) => {
      if (isOtherRouterCall(g.checker, n)) out.push(`${rel(g, sf)}:${line(sf, n)} ${n.expression.getText(sf)}`);
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return out;
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
  if ((ts.isArrowFunction(n) || ts.isFunctionExpression(n)) &&
    (ts.isVariableDeclaration(n.parent) || ts.isPropertyAssignment(n.parent) || ts.isPropertyDeclaration(n.parent)) && n.parent.initializer === n) {
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
    if (child !== (p as { expression?: ts.Node }).expression && isOtherRouterCall(g.checker, p)) {
      return { kind: "error", label: `?? ${rel(g, sf)}:${line(sf, p)} a registration on a router other than app (${p.expression.getText(sf)})` };
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
  const container = ts.isConstructorDeclaration(fn) ? null
    : fn.parent && (ts.isPropertyAssignment(fn.parent) || ts.isPropertyDeclaration(fn.parent)) ? fn.parent.parent : fn.parent;
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
function useOf(g: Graph, sf: ts.SourceFile, id: RefNode, target: ts.Symbol): Use {
  const p = id.parent;
  if (!ts.isIdentifier(id)) {
    // The literal key of an element access: a use of the property, as a property access.
    if (!ts.isElementAccessExpression(p) || p.argumentExpression !== id) return { kind: "escape", label: escape(g, sf, id, "an unexpected literal reference") };
    return useOfExpression(g, sf, id, p);
  }
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
  return useOfExpression(g, sf, id, ts.isPropertyAccessExpression(p) && p.name === id ? p : id);
}

/** What the expression a reference stands for (`f`, `obj.f`, `obj["f"]`) does with the function. */
function useOfExpression(g: Graph, sf: ts.SourceFile, id: RefNode, expr: ts.Node): Use {
  let e: ts.Node = expr;
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
  if (isOtherRouterCall(g.checker, q) && q.arguments.some((a) => a === e)) {
    return { kind: "escape", label: escape(g, sf, id, `a registration on a router other than app (${q.expression.getText(sf)})`) };
  }
  return { kind: "escape", label: escape(g, sf, id, `a value passed on (${ts.SyntaxKind[q.kind]})`) };
}

const escape = (g: Graph, sf: ts.SourceFile, id: RefNode, what: string) => `?? ${rel(g, sf)}:${line(sf, id)} ${id.text}: ${what}`;

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
    // Unresolved references bearing this function's name may be calls the checker could not follow.
    for (const id of g.unresolved.get(symbol.name) ?? []) {
      const sf = id.getSourceFile();
      entries.add(`${escape(g, sf, id, "a reference the checker cannot resolve")}${via}`);
    }
    // A call through a member without a body (an interface, type-literal or abstract member) may dispatch to this
    // member: when a chain function is a member, every such use with its name fails closed.
    const own = keyOf(symbol);
    if (own && typeof own === "object" && "kind" in own && (ts.isMethodDeclaration(own) || ts.isPropertyAssignment(own) ||
      ts.isPropertyDeclaration(own) || ts.isShorthandPropertyAssignment(own) || ts.isGetAccessorDeclaration(own))) {
      for (const { ref, owner } of g.bodiless.get(symbol.name) ?? []) {
        const sf = ref.getSourceFile();
        entries.add(`?? ${rel(g, sf)}:${line(sf, ref)} ${owner}: a use of a member without a body may dispatch to ${symbol.name}${via}`);
      }
    }
    // An access that may reach it without naming it.
    for (const d of g.dynamic) {
      if (!d.keys.has(keyOf(symbol))) continue;
      const sf = d.node.getSourceFile();
      entries.add(`?? ${rel(g, sf)}:${line(sf, d.node)} ${d.what} may reach ${symbol.name}${via}`);
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

/** A part of a SQL text that is not a literal: a template substitution, a variable, a call. */
export const SQL_HOLE = "\u0000";

/**
 * The SQL text of an expression: a string or template literal, or a `+`
 * concatenation with at least one literal operand, each part that is not
 * a literal read as {@link SQL_HOLE}. Null for anything else.
 */
export function sqlText(n: ts.Node): string | null {
  if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return n.text;
  if (ts.isTemplateExpression(n)) return n.head.text + n.templateSpans.map((span) => SQL_HOLE + span.literal.text).join("");
  if (ts.isParenthesizedExpression(n)) return sqlText(n.expression);
  if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = sqlText(n.left);
    const right = sqlText(n.right);
    return left === null && right === null ? null : (left ?? SQL_HOLE) + (right ?? SQL_HOLE);
  }
  return null;
}

/**
 * A write whose table cannot be read from the text: the table is a hole, or
 * nothing follows the keyword. A lock clause (`FOR UPDATE`, `FOR NO KEY
 * UPDATE`) and an upsert's `DO UPDATE` are not writes of a named table.
 */
const UNNAMED_WRITE = new RegExp(`(?<!\\b(?:FOR|KEY|DO|ON) )\\b(?:INSERT INTO|UPDATE|DELETE FROM)\\s*(?:${SQL_HOLE}|$)`);

/** The outermost expression of a `+` chain (through parentheses) that `n` is part of. */
const inConcatenation = (n: ts.Node): boolean => {
  let p = n.parent;
  while (p && ts.isParenthesizedExpression(p)) p = p.parent;
  return !!p && ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.PlusToken && sqlText(p) !== null;
};

/**
 * Every SQL text in src/ (see {@link sqlText}) that `write` matches, by its
 * enclosing route or function ("file name"), with that function's symbol
 * (null for a route, a root's own body, or a fail-closed entry). A text
 * with a write of an unnamed table fails closed: "?? file:line a write
 * whose table is not a literal".
 */
export function writers(g: Graph, write: RegExp): { label: string; symbol: ts.Symbol | null }[] {
  const out = new Map<string, ts.Symbol | null>();
  for (const sf of srcFiles(g.program, g.srcDir)) {
    const visit = (n: ts.Node) => {
      const text = inConcatenation(n) ? null : sqlText(n);
      if (text !== null && write.test(text)) {
        const ctx = enclosingOf(g, sf, n);
        out.set(ctx.kind === "error" ? ctx.label : ctx.kind === "module" ? `?? ${ctx.label}` : ctx.label, ctx.kind === "function" ? ctx.symbol : null);
        return;
      }
      if (text !== null && UNNAMED_WRITE.test(text)) {
        out.set(`?? ${rel(g, sf)}:${line(sf, n)} a write whose table is not a literal`, null);
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
