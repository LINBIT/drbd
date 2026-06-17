#!/usr/bin/env python3
"""
Check that DRBD per-object flag enums fit the ->flags storage word(s), and
that worker-dispatched flags stay in the first machine word.

Background: the flags in 'enum {device,peer_device,connection,resource}_flag'
are used as bit numbers for set_bit()/test_bit() on the matching
'struct drbd_<obj>->flags'.  set_bit(nr, addr) does not wrap a too-large nr
within one word -- it indexes addr[nr / BITS_PER_LONG] -- so a flag whose
value reaches BITS_PER_LONG either corrupts the neighbouring struct member
(scalar storage) or is simply out of range.  This must hold on 32-bit kernels,
where unsigned long is 32 bits, so we evaluate everything against a 32-bit word
(the worst case); CI never builds 32-bit, so a BUILD_BUG_ON would not catch it.

Two invariants are checked, both assuming 32-bit unsigned long:

  1. Storage fit.  For scalar 'unsigned long flags;' the highest flag value
     must be < 32.  For a self-sizing 'unsigned long flags[BITS_TO_LONGS(S)]'
     the sentinel S must be the enum's last/largest enumerator so the array
     grows with the enum automatically.

  2. Word-0 work flags.  get_work_bits() does a cmpxchg() on a single unsigned
     long (flags[0]), so every flag listed in a *_WORK_MASK must have a value
     < 32.

It requires the tree-sitter parser for C. E.g.:
pip install tree_sitter
pip install tree_sitter_c

Usage: python3 checks/check_flag_overflow.py drbd/*.c

Headers are discovered automatically next to the given files, so the enum,
struct and macro definitions in drbd_int.h are picked up even though the
Makefile only passes the .c files.
"""

import sys
import os
import re
import glob

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

C_LANG = Language(tsc.language())

# Worst case: a 32-bit kernel has a 32-bit unsigned long.
LONG_BITS = 32

# enum <obj>_flag  <->  struct drbd_<obj>->flags
FLAG_ENUM_RE = re.compile(r"^(device|peer_device|connection|resource)_flag$")

# *_WORK_MASK macro  ->  enum it draws flags from
WORK_MASK_ENUM = {
    "DRBD_DEVICE_WORK_MASK": "device_flag",
    "DRBD_PEER_DEVICE_WORK_MASK": "peer_device_flag",
}

# A trailing enumerator used only to size an array / count members, not a bit.
SENTINEL_RE = re.compile(r"(_COUNT|_LAST|^NR_|^__)", re.IGNORECASE)


def make_parser():
    return Parser(C_LANG)


def txt(node):
    return node.text.decode()


# ---------------------------------------------------------------------------
# Expression evaluation for enumerator initialisers (= EXPR)
# ---------------------------------------------------------------------------

_BINOPS = {
    "+": lambda a, b: a + b,
    "-": lambda a, b: a - b,
    "*": lambda a, b: a * b,
    "<<": lambda a, b: a << b,
    ">>": lambda a, b: a >> b,
    "|": lambda a, b: a | b,
    "&": lambda a, b: a & b,
}


class EvalError(Exception):
    pass


def eval_expr(node, symbols):
    """Evaluate a constant integer expression node against a name->int dict."""
    t = node.type
    if t == "number_literal":
        s = txt(node).rstrip("uUlL")
        return int(s, 0)
    if t == "identifier":
        name = txt(node)
        if name not in symbols:
            raise EvalError(f"unknown identifier {name!r}")
        return symbols[name]
    if t == "parenthesized_expression":
        inner = [c for c in node.named_children]
        if len(inner) != 1:
            raise EvalError("malformed parenthesized expression")
        return eval_expr(inner[0], symbols)
    if t == "unary_expression":
        op = node.child(0).type
        val = eval_expr(node.named_children[-1], symbols)
        if op == "-":
            return -val
        if op == "~":
            return ~val
        if op == "+":
            return val
        raise EvalError(f"unsupported unary op {op!r}")
    if t == "binary_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        op = node.child_by_field_name("operator")
        if not (left and right and op):
            raise EvalError("malformed binary expression")
        fn = _BINOPS.get(txt(op))
        if fn is None:
            raise EvalError(f"unsupported binary op {txt(op)!r}")
        return fn(eval_expr(left, symbols), eval_expr(right, symbols))
    raise EvalError(f"unsupported expression node {t!r}")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

class Enum:
    def __init__(self, name, path):
        self.name = name
        self.path = path
        self.members = []          # list of (name, value, is_sentinel, row)

    @property
    def real_members(self):
        return [m for m in self.members if not m[2]]


def walk(node):
    yield node
    for c in node.children:
        yield from walk(c)


def parse_file(path, parser, enums, struct_flags, symbols, source_order):
    with open(path, "rb") as f:
        data = f.read()
    tree = parser.parse(data)
    root = tree.root_node

    for node in walk(root):
        if node.type == "enum_specifier":
            _parse_enum(node, path, enums, symbols, source_order)
        elif node.type == "struct_specifier":
            _parse_struct(node, struct_flags)


def _parse_enum(node, path, enums, symbols, source_order):
    name_node = node.child_by_field_name("name")
    body = node.child_by_field_name("body")
    if not name_node or not body:
        return
    name = txt(name_node)
    en = Enum(name, path)
    tracked = bool(FLAG_ENUM_RE.match(name))

    counter = 0
    for child in body.named_children:
        if child.type != "enumerator":
            continue
        ident = child.child_by_field_name("name")
        value_node = child.child_by_field_name("value")
        mname = txt(ident)
        if value_node is not None:
            try:
                counter = eval_expr(value_node, symbols)
            except EvalError as e:
                # Only the flag enums must be evaluated exactly; for the rest a
                # positional fallback is fine and a warning would be noise.
                if tracked:
                    print(f"{path}: WARNING: cannot evaluate value of "
                          f"{mname} ({e}); using positional fallback",
                          file=sys.stderr)
        value = counter
        symbols[mname] = value
        is_sentinel = bool(SENTINEL_RE.search(mname))
        en.members.append((mname, value, is_sentinel, child.start_point[0] + 1))
        counter += 1

    # Track only the flag enums we care about (keep the first definition seen).
    if FLAG_ENUM_RE.match(name) and name not in enums:
        enums[name] = en
        source_order.append(name)


def _parse_struct(node, struct_flags):
    name_node = node.child_by_field_name("name")
    body = node.child_by_field_name("body")
    if not name_node or not body:
        return
    sname = txt(name_node)
    if not sname.startswith("drbd_"):
        return
    for field in body.named_children:
        if field.type != "field_declaration":
            continue
        decl = field.child_by_field_name("declarator")
        if decl is None:
            continue
        # Array form: flags[...]
        if decl.type == "array_declarator":
            inner = decl.child_by_field_name("declarator")
            size = decl.child_by_field_name("size")
            if inner is not None and txt(inner) == "flags":
                struct_flags[sname] = (
                    "array", txt(size) if size is not None else "")
        elif decl.type == "field_identifier" and txt(decl) == "flags":
            struct_flags[sname] = ("scalar", "")


def parse_work_masks(paths):
    """Return {macro_name: [flag, ...]} from '#define X_WORK_MASK ...1UL << FLAG'."""
    masks = {}
    shift_re = re.compile(r"1UL\s*<<\s*([A-Za-z_][A-Za-z0-9_]*)")
    define_re = re.compile(r"#\s*define\s+(\w*WORK_MASK)\b")
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        # Join line continuations so the whole macro body is one string.
        text = text.replace("\\\n", " ")
        for line in text.splitlines():
            m = define_re.search(line)
            if not m:
                continue
            masks[m.group(1)] = shift_re.findall(line)
    return masks


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_storage(enums, struct_flags, errors):
    for ename, en in enums.items():
        obj = FLAG_ENUM_RE.match(ename).group(1)
        sname = f"drbd_{obj}"
        if sname not in struct_flags:
            errors.append(
                f"{en.path}: ERROR: no 'flags' field found in struct {sname} "
                f"for enum {ename}")
            continue
        kind, bound = struct_flags[sname]
        reals = en.real_members
        if not reals:
            continue
        max_name, max_val, _, max_row = max(reals, key=lambda m: m[1])

        if kind == "scalar":
            if max_val >= LONG_BITS:
                errors.append(
                    f"{en.path}:{max_row}: ERROR: enum {ename} reaches bit "
                    f"{max_val} ({max_name}) but struct {sname}.flags is a "
                    f"scalar unsigned long ({LONG_BITS} bits on 32-bit). "
                    f"Convert flags to "
                    f"'unsigned long flags[BITS_TO_LONGS(<sentinel>)]'.")
        else:  # array
            sentinels = [m for m in en.members if m[2]]
            ok = any(bound and s[0] in bound for s in sentinels)
            if not ok:
                errors.append(
                    f"{en.path}: ERROR: struct {sname}.flags is an array sized "
                    f"by '{bound}', which is not a sentinel of enum {ename}; "
                    f"the array will not grow with the enum.")
                continue
            # The sentinel must dominate every real flag.
            for s in sentinels:
                if s[0] in bound and any(m[1] >= s[1] for m in reals):
                    bad = max(reals, key=lambda m: m[1])
                    errors.append(
                        f"{en.path}:{bad[3]}: ERROR: flag {bad[0]}={bad[1]} is "
                        f">= sizing sentinel {s[0]}={s[1]} in enum {ename}; "
                        f"the sentinel must be the last enumerator.")


def check_work_masks(masks, enums, errors):
    for macro, flags in masks.items():
        ename = WORK_MASK_ENUM.get(macro)
        if ename is None or ename not in enums:
            continue
        values = {m[0]: m[1] for m in enums[ename].members}
        for flag in flags:
            val = values.get(flag)
            if val is None:
                errors.append(
                    f"ERROR: {macro} references {flag}, which is not in "
                    f"enum {ename}")
            elif val >= LONG_BITS:
                errors.append(
                    f"ERROR: {macro} flag {flag}={val} is not in word 0 "
                    f"(>= {LONG_BITS}); get_work_bits() does a cmpxchg() on a "
                    f"single unsigned long and would never dispatch it on "
                    f"32-bit. Keep worker-dispatched flags below bit "
                    f"{LONG_BITS}.")


# ---------------------------------------------------------------------------

def gather_files(args):
    """argv files plus every *.h sitting next to them (dedup, stable order)."""
    files = []
    seen = set()
    dirs = set()
    for a in args:
        if os.path.isfile(a):
            rp = os.path.realpath(a)
            if rp not in seen:
                seen.add(rp)
                files.append(a)
            dirs.add(os.path.dirname(rp) or ".")
    for d in sorted(dirs):
        for h in sorted(glob.glob(os.path.join(d, "*.h"))):
            rp = os.path.realpath(h)
            if rp not in seen:
                seen.add(rp)
                files.append(h)
    return files


def main():
    args = sys.argv[1:]
    if not args:
        print(f"Usage: {sys.argv[0]} <file.c> [file2.c ...]", file=sys.stderr)
        sys.exit(1)

    parser = make_parser()
    files = gather_files(args)

    enums = {}
    struct_flags = {}
    symbols = {}
    source_order = []
    for path in files:
        parse_file(path, parser, enums, struct_flags, symbols, source_order)

    masks = parse_work_masks(files)

    errors = []
    check_storage(enums, struct_flags, errors)
    check_work_masks(masks, enums, errors)

    for e in errors:
        print(e)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
