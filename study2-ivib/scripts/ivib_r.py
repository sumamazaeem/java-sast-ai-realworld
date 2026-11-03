#!/usr/bin/env python3
"""IVIB-R: a re-implementation of IVIB's slicing, ISL translation and state annotation
(Zhang et al., IEEE Trans. Reliability 74(3), 2025, Sections III-B and III-C).

Why a re-implementation: in the released code (github.com/KLSEHB/IVIB, slice-project) the slicing
traversals return empty sets and the ISL writer writes nothing (TranslateServiceImpl), and no data
or model is shipped. Only the Python BERT-BiLSTM-CRF code is complete. So this module rebuilds the
missing middle from the paper text, and keeps the released parts as they are:
  - sources and sinks: exactly IVIB's Constants.java lists (spec "ivib"), matched by method name
    like IVIB's MatchMethodName; the paper's sanitiser/validation/string-change functions (Table I)
    are not in the released code, so a short list is reconstructed here (marked RECONSTRUCTED);
  - token naming follows Constants.java prefixes (input_, object_, var_, listVar_, mapVar_, newClass_,
    San_, Chg_, ss_, cond, operator_, func_, constant, vulType);
  - states follow config/properties.py TAG2IDX (taint, n-taint, san, val, conf, chg, novul, sqlvul,
    xssvul, cmdvul, xpathvul); for our 5 CWEs we add pathvul and codevul.

Slicing (Algorithm 1, FIslicing): forward taint walk over the statements of the unit's method from
every source call; a statement enters the slice when it reads or writes a tainted value; calls to
methods defined in the same context (the file, or all files of a Juliet case) are followed with
parameter mapping, up to depth 3 (interprocedural). A slice is emitted only if tainted data reaches a
sink, as in IVIB; a unit with no source-to-sink path has no slice, and IVIB then cannot report it.

Output per unit: list of slices; each slice = list of (token, state); the last token is vulType with
the unit's ground-truth state (novul for label 0).
"""
import json
import re
import sys
from functools import lru_cache

import tree_sitter as ts
import tree_sitter_java as tsj

LANG = ts.Language(tsj.language())
PARSER = ts.Parser(LANG)

# ---- IVIB Constants.java (verbatim) -------------------------------------------------------------
IVIB_SOURCES = {"readLine", "getString", "getParameter", "getQueryString", "getProperty", "getCookies",
                "getAttribute", "getParameterValues", "getParameterMap", "getParameterNames", "getHeader",
                "getParameters", "getHeaders"}
IVIB_SINKS = {"sendError", "println", "execute", "addBatch", "executeBatch", "executeQuery", "executeUpdate",
              "exec", "addCookie", "evaluate", "format", "setAttribute"}
# ---- RECONSTRUCTED from the paper's Table I categories (not in the released code) ----------------
SANITIZERS = {"encodeForHTML", "encodeForHTMLAttribute", "encodeForJavaScript", "encodeForSQL", "encodeForOS",
              "escapeHtml", "escapeHtml4", "escapeSql", "htmlEscape", "encodeForURL", "escape", "quote",
              "setString", "setInt", "setObject", "getCanonicalPath", "normalize", "sanitize", "clean"}
VALIDATORS = {"matches", "isValid", "validate", "isEmpty", "isBlank", "equals", "equalsIgnoreCase", "contains",
              "startsWith", "endsWith", "parseInt", "parseLong", "valueOf", "isDigit", "isLetterOrDigit"}
STR_FUNCS = {"replace", "replaceAll", "replaceFirst", "substring", "trim", "toLowerCase", "toUpperCase",
             "split", "concat", "append", "toString", "decode", "getBytes", "charAt", "join", "format"}
CONTAINER_ADD = {"add", "put", "append", "set", "push", "offer", "addAll", "putAll", "insert", "addElement",
                 "setProperty"}
# Sinks for the two CWEs IVIB does not cover (path traversal, code injection), used by spec "ivib5".
EXTRA_SINKS = {22: {"File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile",
                    "newInputStream", "newOutputStream", "readAllBytes", "newBufferedReader", "copy", "delete"},
               94: {"eval", "parseExpression", "evaluateExpression", "invokeMethod", "loadClass", "forName",
                    "createScript", "executeScript"}}
SINK_CWE = {"executeQuery": 89, "executeUpdate": 89, "execute": 89, "addBatch": 89, "executeBatch": 89,
            "prepareStatement": 89, "prepareCall": 89, "exec": 78, "start": 78, "command": 78,
            "println": 79, "print": 79, "write": 79, "format": 79, "printf": 79, "sendError": 79,
            "addCookie": 79, "setAttribute": 79, "evaluate": 94}
VULSTATE = {89: "sqlvul", 79: "xssvul", 78: "cmdvul", 22: "pathvul", 94: "codevul", 643: "xpathvul"}


def spec(name, llm=None):
    """name: ivib (IVIB lists), ivib5 (IVIB + sinks for 22/94), ivib5p (ivib5 + the unit method's
    String-like parameters are sources: library code receives attacker data through its API),
    llm (ivib5p + LLM-inferred sources/sinks/sanitisers of that project version, union)."""
    src, snk, san = set(IVIB_SOURCES), set(IVIB_SINKS), set(SANITIZERS)
    if name in ("ivib5", "ivib5p", "llm"):
        for s in EXTRA_SINKS.values():
            snk |= s
    if name == "llm" and llm:
        last = lambda k: k.rsplit(".", 1)[-1]  # noqa: E731 - IVIB matches by method name only
        src |= {last(k) for k in llm.get("sources", [])}
        for v in llm.get("sinks", {}).values():
            snk |= {last(k) for k in v}
        for v in llm.get("sanitizers", {}).values():
            san |= {last(k) for k in v}
    return {"sources": src, "sinks": snk, "sanitizers": san, "params": name in ("ivib5p", "llm")}


# ---- parsing helpers -----------------------------------------------------------------------------
def txt(n):
    return n.text.decode("utf-8", "replace")


@lru_cache(maxsize=512)
def parse(code):
    return PARSER.parse(code.encode("utf-8", "replace"))


def methods_in(tree):
    out = []
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type in ("method_declaration", "constructor_declaration"):
            out.append(n)
        stack.extend(n.children)
    return out


def call_name(n):
    if n.type == "method_invocation":
        f = n.child_by_field_name("name")
        return txt(f) if f else None
    if n.type == "object_creation_expression":
        t = n.child_by_field_name("type")
        return txt(t).split("<")[0].rsplit(".", 1)[-1] if t else None
    return None


def walk(n):
    stack = [n]
    while stack:
        x = stack.pop()
        yield x
        stack.extend(reversed(x.children))


def idents(n):
    return {txt(x) for x in walk(n) if x.type == "identifier"}


class Slicer:
    def __init__(self, sp, context_codes):
        self.sp = sp
        self.branch = 0
        self.defs = {}  # method name -> [method nodes] across the context
        for code in context_codes:
            for m in methods_in(parse(code)):
                nm = m.child_by_field_name("name")
                if nm:
                    self.defs.setdefault(txt(nm), []).append(m)

    # state of an expression given the taint map; returns (state or None, tokens)
    def expr(self, n, T, toks):
        st = None
        for x in walk(n):
            if x.type == "method_invocation" or x.type == "object_creation_expression":
                nm = call_name(x)
                obj = x.child_by_field_name("object")
                if nm in self.sp["sources"]:
                    if obj is not None:
                        toks.append((f"object_{txt(obj).rsplit('.', 1)[-1]}", "n-taint"))
                    toks.append((f"input_{nm}", "taint"))
                    st = st or "taint"
                elif nm in self.sp["sanitizers"]:
                    toks.append((f"San_{nm}", "san"))
                    st = "san" if self._args_tainted(x, T) else st
                elif nm in VALIDATORS:
                    toks.append((f"func_{nm}", "val" if self._args_tainted(x, T) else "n-taint"))
                elif nm in STR_FUNCS and self._recv_or_args_tainted(x, T):
                    toks.append((f"Chg_{nm}", "chg"))
                    st = st or "chg"
                elif x.type == "object_creation_expression" and nm:
                    toks.append((f"newClass_{nm}", "n-taint"))
                elif nm and nm in self.defs and self._args_tainted(x, T):
                    ret = self.inline(x, T, toks)
                    st = st or ret
                elif nm:
                    toks.append((f"func_{nm}", "n-taint"))
            elif x.type == "identifier" and txt(x) in T and not self._is_name(x):
                toks.append((f"var_{txt(x)}", T[txt(x)]))
                st = st or T[txt(x)]
            elif x.type in ("string_literal", "decimal_integer_literal", "true", "false", "null_literal"):
                toks.append(("constant", "n-taint"))
            elif x.type == "binary_expression":
                op = x.child_by_field_name("operator")
                if op is not None:
                    toks.append((f"operator_{txt(op)}", "n-taint"))
        return st

    @staticmethod
    def _is_name(x):
        """True when the identifier names a method or field rather than reading a variable."""
        p = x.parent
        if p is None:
            return False
        if p.type == "method_invocation":
            return p.child_by_field_name("name") == x
        if p.type == "field_access":
            return p.child_by_field_name("field") == x
        return p.type == "scoped_identifier"

    def _args_tainted(self, call, T):
        a = call.child_by_field_name("arguments")
        return a is not None and bool(idents(a) & set(T)) or (a is not None and any(
            call_name(y) in self.sp["sources"] for y in walk(a)))

    def _recv_or_args_tainted(self, call, T):
        o = call.child_by_field_name("object")
        return self._args_tainted(call, T) or (o is not None and bool(idents(o) & set(T)))

    def inline(self, call, T, toks, depth=[0]):  # noqa: B006 - recursion depth counter
        if depth[0] >= 3:
            return None
        nm = call_name(call)
        args = [c for c in call.child_by_field_name("arguments").named_children]
        best = None
        for m in self.defs.get(nm, [])[:2]:
            ps = [p.child_by_field_name("name") for p in m.child_by_field_name("parameters").named_children
                  if p.type in ("formal_parameter", "spread_parameter")]
            if len(ps) != len(args):
                continue
            T2 = {}
            for p, a in zip(ps, args):
                s = self.expr(a, T, [])
                if s and p is not None:
                    T2[txt(p)] = s
            if not T2:
                continue
            depth[0] += 1
            body = m.child_by_field_name("body")
            if body is not None:
                ret = self.block(body, T2, toks)
                best = best or ret
            depth[0] -= 1
        return best

    def block(self, body, T, toks, out_sinks=None):
        """Walk statements in order; returns the state of a returned tainted value."""
        ret = None
        for s in body.named_children:
            r = self.stmt(s, T, toks, out_sinks)
            ret = ret or r
        return ret

    def stmt(self, s, T, toks, sinks):
        t = s.type
        if t in ("block", "try_statement", "catch_clause", "finally_clause", "switch_block",
                 "switch_block_statement_group", "constructor_body"):
            ret = None
            for c in s.named_children:
                ret = self.stmt(c, T, toks, sinks) or ret
            return ret
        if t in ("if_statement", "while_statement", "for_statement", "enhanced_for_statement", "do_statement",
                 "switch_expression", "switch_statement"):
            cond = s.child_by_field_name("condition") or s.child_by_field_name("value")
            if cond is not None and idents(cond) & set(T):
                ct = []
                self.expr(cond, T, ct)
                for name in idents(cond) & set(T):  # validated inside the guarded block
                    if any(call_name(x) in VALIDATORS for x in walk(cond)):
                        T[name] = "val"
                toks += [("cond", "n-taint")] + ct + [("cond", "n-taint")]
            if t == "enhanced_for_statement":
                v, it = s.child_by_field_name("name"), s.child_by_field_name("value")
                if v is not None and it is not None and idents(it) & set(T):
                    T[txt(v)] = T[next(iter(idents(it) & set(T)))]
            ret = None
            self.branch += 1  # path-insensitive: an assignment in one branch does not clear taint
            for c in s.named_children:
                if c != cond:
                    ret = self.stmt(c, T, toks, sinks) or ret
            self.branch -= 1
            return ret
        if t == "local_variable_declaration":
            ty = s.child_by_field_name("type")
            for d in s.named_children:
                if d.type != "variable_declarator":
                    continue
                v, val = d.child_by_field_name("name"), d.child_by_field_name("value")
                if val is None:
                    continue
                self._assign(txt(v), val, T, toks, sinks, txt(ty) if ty is not None else "")
            return None
        if t == "expression_statement":
            e = s.named_children[0] if s.named_children else None
            if e is None:
                return None
            if e.type == "assignment_expression":
                lhs, rhs = e.child_by_field_name("left"), e.child_by_field_name("right")
                name = txt(lhs).split("[")[0].rsplit(".", 1)[-1]
                self._assign(name, rhs, T, toks, sinks, "")
                return None
            self._call_stmt(e, T, toks, sinks)
            return None
        if t == "return_statement":
            if s.named_children and idents(s) & set(T):
                tk = []
                st = self.expr(s.named_children[0], T, tk)
                toks += tk
                return st
            return None
        return None

    def _prefix(self, ty):
        if re.search(r"\b(List|Set|Collection|ArrayList|LinkedList|Vector|\w+\[\])", ty):
            return "listVar_"
        if re.search(r"\bMap\b|HashMap|Properties", ty):
            return "mapVar_"
        if ty in ("String", "StringBuilder", "StringBuffer", "char[]", "") or ty[:1].islower():
            return "var_"
        return "object_"

    def _assign(self, name, val, T, toks, sinks, ty):
        tk = []
        st = self.expr(val, T, tk)
        self._sinks_in(val, T, toks, sinks)
        if st:
            T[name] = st
            toks += tk + [(f"{self._prefix(ty)}{name}", st)]
        elif name in T and not self.branch:
            del T[name]  # overwritten with untainted data on the straight-line path

    def _call_stmt(self, e, T, toks, sinks):
        if e.type == "method_invocation":
            nm, obj = call_name(e), e.child_by_field_name("object")
            if nm in CONTAINER_ADD and obj is not None and self._args_tainted(e, T):
                tk = []
                st = self.expr(e.child_by_field_name("arguments"), T, tk)
                base = txt(obj).split("[")[0].rsplit(".", 1)[-1]
                T[base] = st or "taint"
                toks += tk + [(f"listVar_{base}", T[base])]
                return
        self._sinks_in(e, T, toks, sinks)
        if e.type in ("method_invocation", "object_creation_expression") and call_name(e) in self.defs \
                and self._args_tainted(e, T):
            self.inline(e, T, toks)

    def _sinks_in(self, n, T, toks, sinks):
        for x in walk(n):
            nm = call_name(x)
            if nm in self.sp["sinks"] and self._recv_or_args_tainted(x, T) if x.type == "method_invocation" \
                    else (x.type == "object_creation_expression" and nm in self.sp["sinks"]
                          and self._args_tainted(x, T)):
                tk = []
                obj = x.child_by_field_name("object")
                if obj is not None:
                    tk.append((f"object_{txt(obj).split('(')[0].rsplit('.', 1)[-1]}", "n-taint"))
                a = x.child_by_field_name("arguments")
                st = self.expr(a, T, tk) if a is not None else None
                if obj is not None and idents(obj) & set(T):
                    st = st or T[next(iter(idents(obj) & set(T)))]
                toks += tk + [(f"ss_{nm}", st or "taint")]
                if sinks is not None:
                    sinks.append(nm)


def slice_unit(method_code, context_codes, sp, final_state, method_name=None):
    """Return the ISL sequence of the unit's method, or None when no tainted data reaches a sink."""
    tree = parse(method_code)
    ms = methods_in(tree)
    if not ms or tree.root_node.has_error and not tree.root_node.named_children[0].type.endswith("declaration"):
        tree = parse("class __U {\n" + method_code + "\n}")
        ms = methods_in(tree)
    if method_name:
        ms = [m for m in ms if m.child_by_field_name("name") is not None
              and txt(m.child_by_field_name("name")) == method_name] or ms
    if not ms:
        return None
    sl = Slicer(sp, list(context_codes))
    toks, sinks = [], []
    body = ms[-1].child_by_field_name("body")
    if body is None:
        return None
    T = {}
    if sp.get("params"):
        for p in ms[-1].child_by_field_name("parameters").named_children:
            ty, nm = p.child_by_field_name("type"), p.child_by_field_name("name")
            if ty is not None and nm is not None and re.search(
                    r"String|char\[\]|byte\[\]|InputStream|Reader|Path|File|Object|Map|List|Request|Entry", txt(ty)):
                T[txt(nm)] = "taint"
                toks += [("input", "taint"), (f"{sl._prefix(txt(ty))}{txt(nm)}", "taint")]
    sl.block(body, T, toks, sinks)
    if not sinks:
        return None
    # IVIB symbolic processing (data.py process): var/object names numbered in order of appearance
    names, seq = {}, []
    for tok, st in toks:
        m = re.match(r"(var_|listVar_|mapVar_|enumVar_|object_)(.+)", tok)
        if m:
            key = (m.group(1), m.group(2))
            names.setdefault(key, f"{m.group(1)}var{sum(1 for k in names if k[0] == m.group(1)) + 1}")
            tok = names[key]
        elif tok.startswith("input_"):
            tok = "input"
        seq.append((tok.lower(), st))
    seq = seq[-198:]  # IVIB MAX_LEN = 200
    seq.append(("vultype", final_state))
    return seq


def final_state(unit):
    return VULSTATE[unit["cwe"]] if unit["label"] else "novul"


if __name__ == "__main__":
    code = sys.stdin.read()
    print(json.dumps(slice_unit(code, [code], spec("ivib5"), "sqlvul")))
