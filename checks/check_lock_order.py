#!/usr/bin/env python3
"""
Find lock ordering violations (ABBA deadlock candidates) by static
analysis, using interprocedural held-lock propagation over the call
graph.

Locks are abstracted to *classes* (the lock variable's field name, like
lockdep's lock classes), not instances.  Two kinds of locks are
recognized:

 - DRBD's hand-rolled exclusion primitives, listed in ACQUIRE_FUNCS /
   RELEASE_FUNCS below.  These are invisible to lockdep (e.g. the
   meta-data IO buffer is an atomic_cmpxchg + wait_event loop).
 - Generic kernel primitives (mutex_lock, spin_lock*, rwlock, rwsem);
   the class is the name of the lock field/variable in the first
   argument, e.g. ``mutex_lock(&resource->conf_update)`` -> conf_update.

In addition, *wrapper inference* handles functions that return with a
lock held (begin_state_change) or release a lock taken elsewhere
(end_state_change): calls to them count as acquire/release events in
their callers.

For every blocking acquire, the analysis records edges "held-class ->
acquired-class".  Held classes come from acquire/release bracketing
within the function (byte order, over-approximated) plus classes that
may be held on entry, propagated top-down through the call graph —
including indirect calls through function-pointer parameters
(``io_fn(device, ...)``) and struct fields (``work->io_fn(...)``).
Cycles in the resulting order graph are reported with one witness call
chain per edge.

Limitations (all over-approximations, so expect candidates that need a
human look, not proofs):
 - lock classes, not instances: same-class nesting (two devices'
   bitmaps) is reported separately via --nesting, not as a cycle
 - context-insensitive: the entry held-set of a function is the union
   over all call sites, so a printed path may be infeasible
 - path-insensitive within a function: a conditionally taken lock is
   considered held until its (last) release in byte order
 - cannot see exclusion that makes a cycle benign (both sides under a
   common outer lock, or single-threaded contexts)

A ``/* lock_order_ok: <reason> */`` comment before an acquire
suppresses edge generation from that site.

Usage: python3 checks/check_lock_order.py [--edges] [--nesting] drbd/*.c
"""

import sys
import os
from collections import defaultdict, deque

from c_analysis import (
    make_parser, text, walk_all, walk_body,
    extract_declarator_name, find_calls,
    find_annotation_regions, is_in_regions,
    iter_function_definitions, resolve_callee,
)

# ---------------------------------------------------------------------------
# Lock model
# ---------------------------------------------------------------------------

# DRBD-specific exclusion primitives: function name -> lock class.
ACQUIRE_FUNCS = {
    "drbd_bm_lock": "bitmap",
    "drbd_bm_slot_lock": "bitmap",
    "drbd_md_get_buffer": "md_buffer",
}
RELEASE_FUNCS = {
    "drbd_bm_unlock": "bitmap",
    "drbd_bm_slot_unlock": "bitmap",
    "drbd_md_put_buffer": "md_buffer",
}

# Generic kernel primitives: name -> blocking?  (a trylock cannot be the
# blocked side of a deadlock, so it opens a held region but emits no
# "-> acquired" edge).  The lock class is derived from the first argument.
GENERIC_ACQUIRE = {
    "mutex_lock": True,
    "mutex_lock_interruptible": True,
    "mutex_lock_killable": True,
    "mutex_trylock": False,
    "spin_lock": True,
    "spin_lock_irq": True,
    "spin_lock_irqsave": True,
    "spin_lock_bh": True,
    "spin_trylock": False,
    "read_lock": True,
    "read_lock_irq": True,
    "read_lock_irqsave": True,
    "read_lock_bh": True,
    "write_lock": True,
    "write_lock_irq": True,
    "write_lock_irqsave": True,
    "write_lock_bh": True,
    "down": True,
    "down_interruptible": True,
    "down_killable": True,
    "down_trylock": False,
    "down_read": True,
    "down_write": True,
    "down_read_trylock": False,
    "down_write_trylock": False,
}
GENERIC_RELEASE = {
    "mutex_unlock",
    "spin_unlock", "spin_unlock_irq", "spin_unlock_irqrestore",
    "spin_unlock_bh",
    "read_unlock", "read_unlock_irq", "read_unlock_irqrestore",
    "read_unlock_bh",
    "write_unlock", "write_unlock_irq", "write_unlock_irqrestore",
    "write_unlock_bh",
    "up", "up_read", "up_write",
}

# Unify classes that name the same lock at different abstraction levels:
# drbd_bm_lock() is mutex_lock(&bitmap->bm_change) underneath.
CLASS_ALIASES = {
    "bm_change": "bitmap",
}

LOCK_ORDER_OK = "lock_order_ok"


def canon(cls):
    return CLASS_ALIASES.get(cls, cls)


def lock_class_from_arg(arg):
    """Derive the lock class from an acquire/release call's first
    argument: ``&resource->req_lock`` -> "req_lock",
    ``&global_state_mutex`` -> "global_state_mutex"."""
    node = arg
    if node.type == "pointer_expression" and node.named_children:
        node = node.named_children[0]
    if node.type == "field_expression":
        field = node.child_by_field_name("field")
        if field:
            return text(field)
    if node.type == "identifier":
        return text(node)
    return None


# ---------------------------------------------------------------------------
# Per-function extraction
# ---------------------------------------------------------------------------

def get_param_names(func_node):
    """Return the ordered list of parameter names (None for unnamed)."""
    decl = func_node.child_by_field_name("declarator")
    if decl is None:
        return []
    for node in walk_all(decl):
        if node.type == "parameter_list":
            names = []
            for param in node.named_children:
                if param.type != "parameter_declaration":
                    continue
                pdecl = param.child_by_field_name("declarator")
                name = extract_declarator_name(pdecl) if pdecl else None
                names.append(name)
            return names
    return []


def _arg_descriptor(node):
    """Classify a call argument: ("amp", name) for &name,
    ("ident", name) for a bare identifier, ("other", None) otherwise."""
    if node.type == "pointer_expression" and node.named_children:
        inner = node.named_children[0]
        if inner.type == "identifier":
            return ("amp", text(inner))
        return ("other", None)
    if node.type == "identifier":
        return ("ident", text(node))
    return ("other", None)


def scan_calls(body):
    """Return [(kind, name, byte, line, args, first_arg_class)] for every
    call expression.  kind is "ident" for foo(...) and "field" for
    x->foo(...); args are _arg_descriptor tuples."""
    details = []
    for node in walk_body(body):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None:
            continue
        args_node = node.child_by_field_name("arguments")
        args = []
        first_arg_class = None
        if args_node:
            named = [a for a in args_node.named_children
                     if a.type != "comment"]
            args = [_arg_descriptor(a) for a in named]
            if named:
                first_arg_class = lock_class_from_arg(named[0])
        line = node.start_point[0] + 1
        if fn.type == "identifier":
            details.append(("ident", text(fn), node.start_byte, line,
                            args, first_arg_class))
        elif fn.type == "field_expression":
            field = fn.child_by_field_name("field")
            if field:
                details.append(("field", text(field), node.start_byte,
                                line, args, None))
    return details


def _rhs_func_ref(node):
    """Return the function/parameter name a RHS refers to, or None."""
    if node.type == "pointer_expression" and node.named_children:
        node = node.named_children[0]
    if node.type == "identifier":
        return text(node)
    return None


def scan_field_assigns(body):
    """Find ``x->fld = ref`` assignments and ``.fld = ref`` initializers
    where ref is an identifier or &identifier.
    Returns [(field_name, ref_name)]."""
    assigns = []
    for node in walk_body(body):
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                continue
            if left.type != "field_expression":
                continue
            field = left.child_by_field_name("field")
            if field is None:
                continue
            ref = _rhs_func_ref(right)
            if ref:
                assigns.append((text(field), ref))
        elif node.type == "initializer_pair":
            value = node.child_by_field_name("value")
            if value is None:
                continue
            ref = _rhs_func_ref(value)
            if not ref:
                continue
            for child in node.children:
                if child.type == "field_designator":
                    for sub in child.children:
                        if sub.type == "field_identifier":
                            assigns.append((text(sub), ref))
    return assigns


class FuncInfo:
    __slots__ = ("name", "filepath", "static", "param_names",
                 "calls", "call_details", "field_assigns",
                 "suppress_regions", "body_end",
                 "rcalls", "events", "regions", "entry", "entry_rel")

    def __init__(self, name, filepath, static):
        self.name = name
        self.filepath = filepath
        self.static = static
        self.param_names = []
        self.calls = []            # find_calls(): (name, byte, line)
        self.call_details = []     # scan_calls()
        self.field_assigns = []    # scan_field_assigns()
        self.suppress_regions = []
        self.body_end = 0
        self.rcalls = []           # resolved: (callee_key, byte, line)
        self.events = []           # (byte, line, kind, cls, blocking)
        self.regions = []          # (cls, start, end, acq_line, blocking)
        self.entry = {}            # cls -> (caller_key, byte, line)
        self.entry_rel = {}        # cls -> byte of first unmatched release


def parse_all_files(filepaths, parser):
    funcs = {}
    for filepath, func_node, name, body, static in \
            iter_function_definitions(filepaths, parser):
        info = FuncInfo(name, filepath, static)
        info.param_names = get_param_names(func_node)
        info.calls = find_calls(body)
        info.call_details = scan_calls(body)
        info.field_assigns = scan_field_assigns(body)
        info.body_end = body.end_byte
        find_annotation_regions(body, info.suppress_regions, LOCK_ORDER_OK)

        key = (filepath, name) if static else name
        funcs[key] = info
    return funcs


# ---------------------------------------------------------------------------
# Function pointer resolution
# ---------------------------------------------------------------------------

def resolve_function_pointers(funcs, name_index):
    """Compute which functions can hide behind function-pointer
    parameters and struct fields.

    Returns (param_targets, field_targets):
      param_targets: (func_key, param_name) -> {function names}
      field_targets: field_name -> {function names}
    """
    param_targets = defaultdict(set)
    field_targets = defaultdict(set)
    param_flows = []   # (src (func_key, param), dst (func_key, param))
    field_flows = []   # (src (func_key, param), dst field_name)

    for fkey, info in funcs.items():
        for kind, name, byte, line, args, _cls in info.call_details:
            if kind != "ident":
                continue
            ck = resolve_callee(info, name, funcs)
            if ck is None:
                continue
            cparams = funcs[ck].param_names
            for i, (akind, aname) in enumerate(args):
                if i >= len(cparams) or cparams[i] is None or aname is None:
                    continue
                dst = (ck, cparams[i])
                if aname in info.param_names:
                    param_flows.append(((fkey, aname), dst))
                elif aname in name_index:
                    param_targets[dst].add(aname)
        for fld, ref in info.field_assigns:
            if ref in name_index:
                field_targets[fld].add(ref)
            elif ref in info.param_names:
                field_flows.append(((fkey, ref), fld))

    changed = True
    while changed:
        changed = False
        for src, dst in param_flows:
            new = param_targets.get(src, set()) - param_targets[dst]
            if new:
                param_targets[dst] |= new
                changed = True
        for src, fld in field_flows:
            new = param_targets.get(src, set()) - field_targets[fld]
            if new:
                field_targets[fld] |= new
                changed = True

    return param_targets, field_targets


def resolve_all_calls(funcs, name_index, param_targets, field_targets):
    """Fill info.rcalls: every call resolved to func_keys, including
    indirect calls via function-pointer parameters and struct fields."""
    for fkey, info in funcs.items():
        out = []
        # Direct calls, plus &func references recorded by find_calls()
        # at the outer call position (the caller's held locks are still
        # held when the callee eventually invokes them).
        for name, byte, line in info.calls:
            ck = resolve_callee(info, name, funcs)
            if ck is not None:
                out.append((ck, byte, line))
        # Indirect calls: through a function-pointer parameter or a
        # struct field.  These run at the *inner* call position, i.e.
        # under whatever locks this function has taken.
        for kind, name, byte, line, args, _cls in info.call_details:
            if kind == "ident" and name in info.param_names:
                targets = param_targets.get((fkey, name), ())
            elif kind == "field":
                targets = field_targets.get(name, ())
            else:
                continue
            for t in sorted(targets):
                for tk in name_index.get(t, ()):
                    out.append((tk, byte, line))
        info.rcalls = out


# ---------------------------------------------------------------------------
# Acquire/release events, held regions, wrapper inference
# ---------------------------------------------------------------------------

def compute_events(info, funcs, inferred_acq, inferred_rel):
    """Acquire/release events of a function, in byte order.  Includes
    inferred events for calls to wrapper functions."""
    evs = []
    for kind, name, byte, line, args, cls_arg in info.call_details:
        if kind != "ident":
            continue
        if name in ACQUIRE_FUNCS:
            evs.append((byte, line, "acq", canon(ACQUIRE_FUNCS[name]), True))
        elif name in RELEASE_FUNCS:
            evs.append((byte, line, "rel", canon(RELEASE_FUNCS[name]), True))
        elif name in GENERIC_ACQUIRE:
            if cls_arg:
                evs.append((byte, line, "acq", canon(cls_arg),
                            GENERIC_ACQUIRE[name]))
        elif name in GENERIC_RELEASE:
            if cls_arg:
                evs.append((byte, line, "rel", canon(cls_arg), True))
        else:
            ck = resolve_callee(info, name, funcs)
            if ck is None:
                continue
            for cls in sorted(inferred_rel.get(ck, ())):
                evs.append((byte, line, "rel", cls, True))
            for cls in sorted(inferred_acq.get(ck, ())):
                evs.append((byte, line, "acq", cls, True))
    # At equal byte positions releases sort before acquires
    # (a drop-and-reacquire wrapper splits the caller's region).
    evs.sort(key=lambda e: (e[0], e[2] == "acq"))
    return evs


def pair_events(evs, body_end):
    """Pair acquire/release events per class in byte order.

    Returns (regions, leftover_acquires, unmatched_releases):
      regions: (cls, start_byte, end_byte, acq_line, blocking)
      leftover_acquires: classes acquired but never released (the
        function escapes with the lock held)
      unmatched_releases: cls -> byte of the first release without a
        preceding acquire (the function releases a caller-held lock;
        an entry-held class stops being held there)
    """
    regions = []
    open_stacks = defaultdict(list)
    unmatched = {}
    for byte, line, kind, cls, blocking in evs:
        if kind == "acq":
            open_stacks[cls].append((byte, line, blocking))
        else:
            if open_stacks[cls]:
                b, l, bl = open_stacks[cls].pop()
                regions.append((cls, b, byte, l, bl))
            else:
                unmatched.setdefault(cls, byte)
    leftover = set()
    for cls, stack in open_stacks.items():
        for b, l, bl in stack:
            regions.append((cls, b, body_end, l, bl))
            leftover.add(cls)
    return regions, leftover, unmatched


def compute_regions(funcs):
    """Compute held regions for all functions, with wrapper inference
    run to a fixpoint: a function with a leftover acquire (unmatched
    release) makes every call to it an acquire (release) event in its
    callers.  Inferred sets only grow, so this terminates."""
    inferred_acq = defaultdict(set)
    inferred_rel = defaultdict(set)

    changed = True
    while changed:
        changed = False
        for fkey, info in funcs.items():
            evs = compute_events(info, funcs, inferred_acq, inferred_rel)
            _, leftover, unmatched = pair_events(evs, info.body_end)
            if leftover - inferred_acq[fkey]:
                inferred_acq[fkey] |= leftover
                changed = True
            if set(unmatched) - inferred_rel[fkey]:
                inferred_rel[fkey] |= set(unmatched)
                changed = True

    for fkey, info in funcs.items():
        info.events = compute_events(info, funcs, inferred_acq, inferred_rel)
        info.regions, _, info.entry_rel = pair_events(info.events,
                                                      info.body_end)


def held_local(info, byte):
    """Lock classes held at *byte* by this function's own regions.
    A region starting exactly at *byte* (the acquire itself, or the
    call being analyzed when it is an acquire wrapper) is not yet held."""
    return {cls for cls, s, e, _l, _bl in info.regions if s < byte <= e}


def held_entry(info, byte):
    """Entry-held classes still held at *byte*.  A drop-and-reacquire
    helper (copy_bitmap: releases the caller's uuid_lock, takes the
    bitmap lock, retakes uuid_lock) releases an entry-held class at its
    first unmatched release; past that byte it is no longer held."""
    return {cls for cls in info.entry
            if byte <= info.entry_rel.get(cls, float("inf"))}


# ---------------------------------------------------------------------------
# Interprocedural propagation of possibly-held-on-entry classes
# ---------------------------------------------------------------------------

def propagate_entry_sets(funcs):
    """Fill info.entry: cls -> (caller_key, call_byte, call_line), the
    first-discovered witness of how cls may be held when this function
    is entered."""
    queue = deque(funcs.keys())
    queued = set(queue)
    while queue:
        fkey = queue.popleft()
        queued.discard(fkey)
        info = funcs[fkey]
        for ck, byte, line in info.rcalls:
            held = held_local(info, byte) | held_entry(info, byte)
            centry = funcs[ck].entry
            for cls in held:
                if cls not in centry:
                    centry[cls] = (fkey, byte, line)
                    if ck not in queued:
                        queue.append(ck)
                        queued.add(ck)


# ---------------------------------------------------------------------------
# Edge collection and cycle detection
# ---------------------------------------------------------------------------

def collect_edges(funcs):
    """Return (edges, nesting).
    edges: (held_cls, acquired_cls) -> witness (fkey, acq_byte, acq_line)
    nesting: [(filepath, line, func_name, cls)] same-class nesting sites."""
    edges = {}
    nesting = []
    for fkey in sorted(funcs.keys(), key=str):
        info = funcs[fkey]
        for cls, s, _e, acq_line, blocking in sorted(info.regions,
                                                     key=lambda r: r[1]):
            if not blocking:
                continue
            if is_in_regions(s, info.suppress_regions):
                continue
            held = held_local(info, s) | held_entry(info, s)
            for h in sorted(held):
                if h == cls:
                    nesting.append((info.filepath, acq_line, info.name, cls))
                    continue
                if (h, cls) not in edges:
                    edges[(h, cls)] = (fkey, s, acq_line)
    return edges, nesting


def find_cycles(edges):
    """Tarjan SCC over the class order graph; return SCCs with a cycle."""
    graph = defaultdict(set)
    nodes = set()
    for h, c in edges:
        graph[h].add(c)
        nodes.add(h)
        nodes.add(c)

    index_of = {}
    lowlink = {}
    on_stack = set()
    stack = []
    sccs = []
    counter = [0]

    def strongconnect(v):
        # Iterative Tarjan to avoid recursion limits
        work = [(v, iter(sorted(graph.get(v, ()))))]
        index_of[v] = lowlink[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        while work:
            node, it = work[-1]
            advanced = False
            for w in it:
                if w not in index_of:
                    index_of[w] = lowlink[w] = counter[0]
                    counter[0] += 1
                    stack.append(w)
                    on_stack.add(w)
                    work.append((w, iter(sorted(graph.get(w, ())))))
                    advanced = True
                    break
                elif w in on_stack:
                    lowlink[node] = min(lowlink[node], index_of[w])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[node])
            if lowlink[node] == index_of[node]:
                scc = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    scc.append(w)
                    if w == node:
                        break
                if len(scc) > 1:
                    sccs.append(sorted(scc))

    for v in sorted(nodes):
        if v not in index_of:
            strongconnect(v)
    return sccs


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def build_chain(funcs, fkey, acq_byte, acq_line, acquired, held):
    """Reconstruct a witness call chain: where *held* was acquired, the
    calls leading to *fkey*, and the acquire of *acquired* there."""
    lines = []
    cur, byte = fkey, acq_byte
    visited = set()
    while True:
        info = funcs[cur]
        local = [(s, l) for cls, s, e, l, _bl in info.regions
                 if cls == held and s < byte <= e]
        if local:
            _s, l = max(local)
            lines.append(f"{info.name}() acquires {held}"
                         f"  {info.filepath}:{l}")
            break
        w = info.entry.get(held)
        if w is None or cur in visited:
            lines.append(f"{info.name}() entered with {held} held"
                         f"  {info.filepath}")
            break
        visited.add(cur)
        caller, cbyte, cline = w
        lines.append(f"{funcs[caller].name}() calls {info.name}()"
                     f"  {funcs[caller].filepath}:{cline}")
        cur, byte = caller, cbyte
    lines.reverse()
    info = funcs[fkey]
    lines.append(f"{info.name}() acquires {acquired}"
                 f"  {info.filepath}:{acq_line}")
    return lines


def report_cycles(funcs, edges, sccs):
    for scc in sccs:
        scc_set = set(scc)
        print(f"== Lock order cycle among: {', '.join(scc)} ==")
        for (h, c), (fkey, byte, line) in sorted(edges.items(),
                                                 key=lambda kv: kv[0]):
            if h not in scc_set or c not in scc_set:
                continue
            print(f"\n  {h} -> {c}:")
            for step in build_chain(funcs, fkey, byte, line, c, h):
                print(f"    {step}")
        print()


def report_edges(funcs, edges):
    for (h, c), (fkey, _byte, line) in sorted(edges.items(),
                                              key=lambda kv: kv[0]):
        info = funcs[fkey]
        print(f"{h} -> {c}  ({info.name}()  {info.filepath}:{line})")


def report_nesting(nesting):
    for filepath, line, name, cls in sorted(set(nesting)):
        print(f"same-class nesting of {cls} in {name}()  {filepath}:{line}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]
    show_edges = "--edges" in args
    show_nesting = "--nesting" in args
    args = [a for a in args if a not in ("--edges", "--nesting")]

    if not args:
        print(f"Usage: {sys.argv[0]} [--edges] [--nesting] "
              f"<file.c> [file2.c ...]", file=sys.stderr)
        sys.exit(1)

    parser = make_parser()
    filepaths = [f for f in args if os.path.isfile(f)]

    funcs = parse_all_files(filepaths, parser)

    name_index = defaultdict(list)
    for key, info in funcs.items():
        name_index[info.name].append(key)

    param_targets, field_targets = resolve_function_pointers(funcs,
                                                             name_index)
    resolve_all_calls(funcs, name_index, param_targets, field_targets)
    compute_regions(funcs)
    propagate_entry_sets(funcs)
    edges, nesting = collect_edges(funcs)

    if show_edges:
        report_edges(funcs, edges)
        print()
    if show_nesting:
        report_nesting(nesting)
        print()

    sccs = find_cycles(edges)
    report_cycles(funcs, edges, sccs)

    sys.exit(1 if sccs else 0)


if __name__ == "__main__":
    main()
