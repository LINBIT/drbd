#!/usr/bin/env python3
"""
Find functions that access ->ldev or ->bitmap without proper
get_ldev()/put_ldev() protection, using bottom-up call graph analysis.

Pass all C files in a single invocation so the tool can build a complete
call graph and transitively verify that callers hold ldev.

It requires the tree-sitter parser for C. E.g.:
pip install tree_sitter
pip install tree_sitter_c

Usage: python3 checks/check_ldev_access.py drbd/*.c
"""

import sys
import os
from collections import defaultdict

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

C_LANG = Language(tsc.language())

GET_LDEV = {"get_ldev", "get_ldev_if_state"}
PUT_LDEV = {"put_ldev"}
LDEV_SAFE_RE = "ldev_safe"
LDEV_REF_TRANSFER_RE = "ldev_ref_transfer"


def make_parser():
    return Parser(C_LANG)


def text(node):
    return node.text.decode() if node.text else ""


def walk_all(node):
    yield node
    for child in node.children:
        yield from walk_all(child)


def walk_body(node):
    """Walk all nodes in a function body, skipping nested function_definitions.

    Macro invocations can cause tree-sitter to misparse subsequent real
    function definitions as nested inside a fake outer function.  When we
    analyse a function's body we must not descend into those nested
    function_definitions — they are handled as separate top-level entries.
    """
    yield node
    for child in node.children:
        if child.type == "function_definition":
            continue
        yield from walk_body(child)


# ---------------------------------------------------------------------------
# Function extraction
# ---------------------------------------------------------------------------

def find_function_definitions(root):
    """Yield all function_definition nodes in the tree.

    We walk the full tree instead of only looking at root.children because
    unexpanded macro invocations can cause tree-sitter to misparse large
    chunks of a file as a single function_definition whose body then
    contains the real function definitions.

    We skip function_definitions whose body contains another
    function_definition — those are typically misparse artifacts.
    However, real functions may also contain nested function_definitions
    when tree-sitter misinterprets a macro call (e.g. page_chain_for_each)
    as a function definition.  We distinguish the two cases by checking
    whether the outer function has a real C return type.
    """
    for node in walk_all(root):
        if node.type != "function_definition":
            continue
        body = node.child_by_field_name("body")
        if body and _contains_nested_func(body):
            if not _has_real_return_type(node):
                continue
        yield node


def _contains_nested_func(body):
    """Check if a compound_statement contains a nested function_definition."""
    for node in walk_all(body):
        if node is body:
            continue
        if node.type == "function_definition":
            return True
    return False


def _has_real_return_type(func_node):
    """Check if a function_definition has a recognizable C return type.

    Real functions have type specifiers like int, void, bool, unsigned,
    struct, enum, or typedef names matching common patterns.  Misparse
    artifacts have the macro name as "type" (e.g. EXPORT_SYMBOL).
    """
    for child in func_node.children:
        if child.type in ("primitive_type", "sized_type_specifier",
                          "struct_specifier", "enum_specifier",
                          "union_specifier", "storage_class_specifier"):
            return True
        if child.type == "type_identifier":
            name = text(child)
            if name[0].islower():
                return True
        if child.type in ("compound_statement", "function_declarator"):
            break
    return False


def get_function_name(func_node):
    decl = func_node.child_by_field_name("declarator")
    if decl is None:
        return None
    while decl.type in ("pointer_declarator", "parenthesized_declarator"):
        for child in decl.named_children:
            if child.type in ("function_declarator", "pointer_declarator",
                              "parenthesized_declarator"):
                decl = child
                break
        else:
            break
    if decl.type == "function_declarator":
        ident = decl.child_by_field_name("declarator")
        if ident and ident.type == "identifier":
            return text(ident)
    return None


def is_static(func_node):
    """Check if a function definition has 'static' storage class."""
    for child in func_node.children:
        if child.type == "storage_class_specifier" and text(child) == "static":
            return True
        if child.type in ("compound_statement", "function_declarator"):
            break
    return False


# ---------------------------------------------------------------------------
# Node queries
# ---------------------------------------------------------------------------

def _extract_struct_type(node):
    """Return the struct tag from a declaration type, e.g. ``"drbd_device"``
    for ``struct drbd_device *foo``, or *None* if not a struct type."""
    for child in node.children:
        if child.type == "struct_specifier":
            for sc in child.children:
                if sc.type == "type_identifier":
                    return text(sc)
    return None


def _extract_declarator_name(decl):
    """Dig through pointer_declarator / init_declarator to find the identifier."""
    for node in walk_all(decl):
        if node.type == "identifier":
            return text(node)
    return None


def build_type_map(func_node, body):
    """Build a mapping *variable name* → *struct tag* for parameters and
    local declarations that are struct pointer types."""
    type_map = {}  # name -> struct tag, e.g. "device" -> "drbd_device"

    # Function parameters
    decl = func_node.child_by_field_name("declarator")
    if decl:
        for node in walk_all(decl):
            if node.type == "parameter_list":
                for param in node.named_children:
                    if param.type != "parameter_declaration":
                        continue
                    tag = _extract_struct_type(param)
                    if tag is None:
                        continue
                    pdecl = param.child_by_field_name("declarator")
                    if pdecl:
                        name = _extract_declarator_name(pdecl)
                        if name:
                            type_map[name] = tag
                break

    # Local variable declarations in body
    for node in walk_body(body):
        if node.type != "declaration":
            continue
        tag = _extract_struct_type(node)
        if tag is None:
            continue
        for child in node.named_children:
            if child.type in ("init_declarator", "pointer_declarator",
                              "identifier"):
                name = _extract_declarator_name(child)
                if name:
                    type_map[name] = tag
    return type_map


def _is_null_check(node):
    """Check if a field_expression is used in a NULL / non-NULL test.

    Matches ``expr == NULL``, ``expr != NULL`` (and reversed),
    ``!expr``, bare truthiness tests (``if (expr)``) and boolean
    operands (``expr && ...``, ``... || expr``).  These do not
    dereference the pointer so they are safe without get_ldev().
    """
    parent = node.parent
    if parent is None:
        return False

    # !device->ldev
    if parent.type == "unary_expression":
        for child in parent.children:
            if child.type == "!" or text(child) == "!":
                return True

    # device->ldev == NULL  /  NULL != device->ldev  etc.
    if parent.type == "binary_expression":
        left = parent.child_by_field_name("left")
        right = parent.child_by_field_name("right")
        if left is not None and right is not None:
            other = right if left.id == node.id else left
            op_text = ""
            for child in parent.children:
                if child.type in ("==", "!="):
                    op_text = child.type
                    break
            if op_text in ("==", "!=") and text(other) in ("NULL", "0"):
                return True

    # device->bitmap && device->ldev  (operand of && or ||)
    if parent.type == "binary_expression":
        for child in parent.children:
            if child.type in ("&&", "||"):
                return True

    # if (device->ldev)  — bare truthiness as condition
    if parent.type == "parenthesized_expression":
        grandparent = parent.parent
        if grandparent and grandparent.type in (
                "if_statement", "while_statement", "for_statement"):
            if parent == grandparent.child_by_field_name("condition"):
                return True

    return False


def find_field_accesses(body, field_names, type_map):
    """Find all ``->ldev`` / ``->bitmap`` accesses on ``struct drbd_device``.

    Uses *type_map* to resolve the struct type of the left-hand side.
    Skips pure NULL checks (``== NULL``, ``!= NULL``, ``!ptr``) since
    those do not dereference the pointer.
    Returns list of (byte_pos, line, col, field_name).
    """
    results = []
    for node in walk_body(body):
        if node.type != "field_expression":
            continue
        # Only match -> (not .)
        if not any(c.type == "->" for c in node.children):
            continue
        field = node.child_by_field_name("field")
        if not field or text(field) not in field_names:
            continue
        arg = node.child_by_field_name("argument")
        if not arg or arg.type != "identifier":
            continue
        if type_map.get(text(arg)) != "drbd_device":
            continue
        if _is_null_check(node):
            continue
        results.append((
            field.start_byte,
            field.start_point[0] + 1,
            field.start_point[1] + 1,
            text(field),
        ))
    return results


def _build_func_ptr_map(body):
    """Build a mapping of local variables to function names they point to.

    Scans for ``var = &func_name`` assignments and returns a dict
    *var_name* → set of *func_names*.  A variable may be assigned
    different functions on different code paths.
    """
    fptr_map = defaultdict(set)
    for node in walk_body(body):
        if node.type != "assignment_expression":
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if not left or left.type != "identifier" or not right:
            continue
        if right.type == "pointer_expression":
            for child in right.children:
                if child.type == "identifier":
                    fptr_map[text(left)].add(text(child))
    return fptr_map


def find_calls(body):
    """Find all function calls in body, including indirect calls via
    function pointers passed as arguments.

    Returns list of (callee_name, byte_pos, line).

    For a direct call like ``foo()``, records ``foo`` at the call position.
    For a function reference passed as argument like
    ``drbd_bitmap_io(dev, &drbd_bm_read, ...)``, records ``drbd_bm_read``
    at the outer call position — this means the protection context
    (get_ldev/put_ldev bracket) of the outer call site also covers the
    indirectly invoked function.

    Also handles the case where a function pointer is first assigned to
    a local variable (``io_func = &drbd_bm_read``) and the variable is
    then passed as an argument.
    """
    fptr_map = _build_func_ptr_map(body)
    results = []
    for node in walk_body(body):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn and fn.type == "identifier":
            results.append((text(fn), node.start_byte,
                            node.start_point[0] + 1))
        # Also check arguments for function references (&func),
        # including inside ternary expressions like
        # ``cond ? &func_a : &func_b``.
        args = node.child_by_field_name("arguments")
        if args:
            for desc in walk_all(args):
                if desc.type == "pointer_expression":
                    for child in desc.children:
                        if child.type == "identifier":
                            results.append((text(child),
                                            node.start_byte,
                                            node.start_point[0] + 1))
                # Variable that holds a function pointer
                if desc.type == "identifier" and desc.parent == args:
                    for fname in fptr_map.get(text(desc), ()):
                        results.append((fname, node.start_byte,
                                        node.start_point[0] + 1))
    return results


def contains_call(node, func_names):
    """Check if node's subtree contains a call to any of func_names."""
    for n in walk_body(node):
        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            if fn and text(fn) in func_names:
                return True
    return False


def _has_ldev_safe(body):
    """Check if a function body contains a /* ldev_safe: ... */ comment."""
    for n in walk_body(body):
        if n.type == "comment" and LDEV_SAFE_RE in text(n):
            return True
    return False


def _has_ldev_ref_transfer_func(body):
    """Check if a function body has a function-level ``/* ldev_ref_transfer: ... */``
    comment among its initial declarations/comments (before the first
    non-declaration/non-comment child)."""
    for child in body.children:
        if child.type in ("comment", "declaration", "{", "}"):
            if child.type == "comment" and LDEV_REF_TRANSFER_RE in text(child):
                return True
            continue
        break
    return False


def is_bail_out(node):
    """Check if a statement exits the current scope."""
    if node.type in ("return_statement", "goto_statement",
                     "continue_statement", "break_statement"):
        return True
    if node.type == "compound_statement":
        stmts = [c for c in node.named_children if c.type != "comment"]
        if stmts and is_bail_out(stmts[-1]):
            return True
    return False


# ---------------------------------------------------------------------------
# Protection analysis
# ---------------------------------------------------------------------------

def find_protected_regions(body):
    """Return list of (start_byte, end_byte) for regions protected by
    get_ldev()/put_ldev() brackets or ldev_safe() assertions."""
    regions = []
    _analyze_block(body, regions)
    _find_ldev_safe_comment_regions(body, regions)
    _find_ldev_ref_transfer_function_region(body, regions)
    return regions


def _find_annotation_regions(body, regions, annotation):
    """Find comments containing *annotation* and mark the next sibling as a region.

    Tree-sitter places the comment as a child node immediately before
    the node it annotates, regardless of nesting level (statement,
    assignment RHS, if-condition, ternary branch, etc.).
    """
    for node in walk_body(body):
        children = node.children
        for i, child in enumerate(children):
            if child.type != "comment" or annotation not in text(child):
                continue
            # Find next non-comment sibling
            for j in range(i + 1, len(children)):
                sibling = children[j]
                if sibling.type != "comment":
                    regions.append((sibling.start_byte, sibling.end_byte))
                    break


def _find_ldev_safe_comment_regions(body, regions):
    """Find ``/* ldev_safe: ... */`` comments and mark the next sibling as protected."""
    _find_annotation_regions(body, regions, LDEV_SAFE_RE)


def _find_ldev_ref_transfer_function_region(body, regions):
    """When a function-level ``/* ldev_ref_transfer: ... */`` is present,
    add a region from body start to the first ``put_ldev()`` call (inclusive),
    or to body end if no ``put_ldev()`` exists (ref delegated)."""
    if not _has_ldev_ref_transfer_func(body):
        return
    # Find the first put_ldev() call in the body
    for node in walk_body(body):
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn and text(fn) in PUT_LDEV:
                regions.append((body.start_byte, node.end_byte))
                return
    # No put_ldev() — ref is delegated; protect entire body
    regions.append((body.start_byte, body.end_byte))


def _analyze_block(block, regions):
    all_children = list(block.named_children)
    stmts = [c for c in all_children if c.type != "comment"]

    # Track variables assigned from get_ldev/get_ldev_if_state
    ldev_vars = set()
    _collect_ldev_vars(stmts, ldev_vars)

    i = 0
    while i < len(stmts):
        stmt = stmts[i]

        # Pattern A: if (!get_ldev(...)) <bail-out>;
        if _is_negated_get_ldev_if(stmt):
            put_idx = _find_last_put_ldev_index(stmts, i + 1)
            if put_idx is not None:
                regions.append((stmt.end_byte, stmts[put_idx].end_byte))
                for j in range(i + 1, put_idx):
                    _recurse_children(stmts[j], regions)
                i = put_idx + 1
                continue
            else:
                regions.append((stmt.end_byte, block.end_byte))
                for j in range(i + 1, len(stmts)):
                    _recurse_children(stmts[j], regions)
                break

        # Pattern B: if (get_ldev(...)) { body }
        pos_body = _is_positive_get_ldev_if(stmt)
        if pos_body is not None:
            regions.append((pos_body.start_byte, pos_body.end_byte))
            _analyze_block(pos_body, regions)
            # Detect ``var = true;`` inside the body -- the variable
            # acts as a deferred ldev guard for later if (var) blocks.
            _collect_ldev_flag_vars(pos_body, ldev_vars)
            i += 1
            continue

        # Pattern C: if (ldev_var) { body } or if (ldev_var && ...) stmt
        # where ldev_var was assigned from get_ldev/get_ldev_if_state
        if ldev_vars:
            ldev_var_body = _is_ldev_var_guard(stmt, ldev_vars)
            if ldev_var_body is not None:
                regions.append((ldev_var_body.start_byte,
                                ldev_var_body.end_byte))
                _analyze_block(ldev_var_body, regions)
                i += 1
                continue

        # Pattern D: ldev_var ? consequence : alternative
        # Mark the consequence of ternary expressions guarded by an
        # ldev variable as protected.
        if ldev_vars:
            _find_ternary_ldev_guards(stmt, ldev_vars, regions)

        _recurse_children(stmt, regions)
        i += 1


def _collect_ldev_vars(stmts, ldev_vars):
    """Find variables assigned from get_ldev()/get_ldev_if_state().

    Detects both ``bool have_ldev = get_ldev_if_state(...)`` (declaration
    with init) and ``have_ldev = get_ldev_if_state(...)`` (assignment).
    """
    for stmt in stmts:
        # Declaration: bool have_ldev = get_ldev_if_state(...);
        if stmt.type == "declaration":
            for child in stmt.named_children:
                if child.type == "init_declarator":
                    value = child.child_by_field_name("value")
                    if value and contains_call(value, GET_LDEV):
                        decl = child.child_by_field_name("declarator")
                        if decl:
                            name = _extract_declarator_name(decl)
                            if name:
                                ldev_vars.add(name)
        # Assignment: have_ldev = get_ldev_if_state(...);
        if stmt.type == "expression_statement":
            for child in stmt.named_children:
                if child.type == "assignment_expression":
                    left = child.child_by_field_name("left")
                    right = child.child_by_field_name("right")
                    if (left and left.type == "identifier" and
                            right and contains_call(right, GET_LDEV)):
                        ldev_vars.add(text(left))


def _collect_ldev_flag_vars(body, ldev_vars):
    """Find variables assigned inside an if (get_ldev()) body.

    When code does::

        if (get_ldev(device)) {
            have_ldev = true;
            // or: peer_md = device->ldev->md.peers;
            ...
        }
        ...
        if (have_ldev) { /* ldev still held */ }

    the variable acts as a deferred ldev guard: being non-zero/non-NULL
    implies that get_ldev() succeeded and put_ldev() has not yet been called.
    """
    for child in body.named_children:
        if child.type != "expression_statement":
            continue
        for expr in child.named_children:
            if expr.type != "assignment_expression":
                continue
            left = expr.child_by_field_name("left")
            if left and left.type == "identifier":
                ldev_vars.add(text(left))


def _is_ldev_var_guard(stmt, ldev_vars):
    """Detect ``if (var) { body }`` or ``if (var && ...) { body }``
    where *var* is a known ldev guard variable.

    Returns the compound_statement body, or None.
    """
    if stmt.type != "if_statement":
        return None
    cond = stmt.child_by_field_name("condition")
    consequence = stmt.child_by_field_name("consequence")
    if cond is None or consequence is None:
        return None
    # Check if condition references an ldev var, either directly or
    # as the left side of &&.
    cond_inner = cond
    # parenthesized_expression wraps the condition
    if cond_inner.type == "parenthesized_expression" and cond_inner.named_children:
        cond_inner = cond_inner.named_children[0]
    found = False
    if cond_inner.type == "identifier" and text(cond_inner) in ldev_vars:
        found = True
    elif cond_inner.type == "binary_expression":
        op = cond_inner.child_by_field_name("operator")
        left = cond_inner.child_by_field_name("left")
        if op and text(op) == "&&" and left:
            if left.type == "identifier" and text(left) in ldev_vars:
                found = True
    if not found:
        return None
    if consequence.type == "compound_statement":
        return consequence
    return None


def _find_ternary_ldev_guards(node, ldev_vars, regions):
    """Find ``ldev_var ? consequence : alternative`` and mark *consequence*
    as a protected region."""
    for n in walk_body(node):
        if n.type != "conditional_expression":
            continue
        cond = n.child_by_field_name("condition")
        consequence = n.child_by_field_name("consequence")
        if cond is None or consequence is None:
            continue
        if cond.type == "identifier" and text(cond) in ldev_vars:
            regions.append((consequence.start_byte, consequence.end_byte))


def _is_negated_get_ldev_if(stmt):
    if stmt.type != "if_statement":
        return False
    cond = stmt.child_by_field_name("condition")
    consequence = stmt.child_by_field_name("consequence")
    if cond is None or consequence is None:
        return False
    if not is_bail_out(consequence):
        return False
    cond_text = text(cond).replace(" ", "").replace("\t", "").replace("\n", "")
    for fn in GET_LDEV:
        if f"!{fn}(" in cond_text:
            return True
    return False


def _is_positive_get_ldev_if(stmt):
    if stmt.type != "if_statement":
        return None
    cond = stmt.child_by_field_name("condition")
    consequence = stmt.child_by_field_name("consequence")
    if cond is None or consequence is None:
        return None
    if not contains_call(cond, GET_LDEV):
        return None
    cond_text = text(cond).replace(" ", "").replace("\t", "").replace("\n", "")
    for fn in GET_LDEV:
        if f"!{fn}(" in cond_text:
            return None
    if consequence.type == "compound_statement":
        return consequence
    return None


def _find_last_put_ldev_index(stmts, start_idx):
    """Find the last put_ldev() in the statement list.

    When ``if (!get_ldev()) bail;`` is followed by code with multiple
    exit paths (normal return + goto error path), each path has its own
    put_ldev(). The protected region extends to the last one.
    """
    last = None
    for i in range(start_idx, len(stmts)):
        if contains_call(stmts[i], PUT_LDEV):
            last = i
    return last


def _recurse_children(node, regions):
    """Descend into children looking for compound_statements to analyze."""
    if node.type == "compound_statement":
        _analyze_block(node, regions)
        return
    # Handle else-if (get_ldev(...)) { body } -- tree-sitter nests these as
    # an if_statement inside the parent's alternative, so _analyze_block
    # never sees them as top-level statements.
    if node.type == "if_statement":
        pos_body = _is_positive_get_ldev_if(node)
        if pos_body is not None:
            regions.append((pos_body.start_byte, pos_body.end_byte))
            _analyze_block(pos_body, regions)
            alt = node.child_by_field_name("alternative")
            if alt:
                _recurse_children(alt, regions)
            return
    for child in node.named_children:
        _recurse_children(child, regions)


def is_in_regions(byte_pos, regions):
    return any(start <= byte_pos <= end for start, end in regions)


# ---------------------------------------------------------------------------
# Balanced get_ldev/put_ldev exit-path analysis
# ---------------------------------------------------------------------------

def _get_ldev_call_line(if_stmt):
    """Extract the line number of the get_ldev() call from an if-statement."""
    cond = if_stmt.child_by_field_name("condition")
    if cond:
        for node in walk_all(cond):
            if node.type == "call_expression":
                fn = node.child_by_field_name("function")
                if fn and text(fn) in GET_LDEV:
                    return node.start_point[0] + 1
    return if_stmt.start_point[0] + 1


def _is_unconditional_put_ldev_stmt(stmt):
    """Check if *stmt* unconditionally executes ``put_ldev()``.

    Matches:
    - ``expression_statement`` containing a ``put_ldev()`` call
    - ``labeled_statement`` whose child statement is such an expression
    """
    if stmt.type == "expression_statement":
        return contains_call(stmt, PUT_LDEV)
    if stmt.type == "labeled_statement":
        for child in stmt.named_children:
            if child.type == "statement_identifier":
                continue
            return _is_unconditional_put_ldev_stmt(child)
    return False


def _has_preceding_put_ldev(return_node, stop_node):
    """Walk up from *return_node* to *stop_node*, checking at each
    ``compound_statement`` level for a preceding sibling that
    unconditionally executes ``put_ldev()``.
    """
    node = return_node
    while node is not None and node != stop_node:
        parent = node.parent
        if parent is None:
            break
        if parent.type in ("compound_statement", "case_statement"):
            for sibling in parent.named_children:
                if sibling.start_byte >= node.start_byte:
                    break
                if _is_unconditional_put_ldev_stmt(sibling):
                    return True
        node = parent
    return False


def _is_inside_pattern_b(node, func_body, guard_stmt):
    """Check if *node* is inside a positive ``if (get_ldev()) { … }`` body."""
    ancestor = node.parent
    while ancestor is not None and ancestor != func_body:
        parent = ancestor.parent
        if (parent is not None and
                parent.type == "if_statement" and
                parent != guard_stmt):
            consequence = parent.child_by_field_name("consequence")
            if consequence == ancestor:
                cond = parent.child_by_field_name("condition")
                if cond and contains_call(cond, GET_LDEV):
                    cond_text = text(cond).replace(" ", "")
                    if not any(f"!{fn}(" in cond_text for fn in GET_LDEV):
                        return True
        ancestor = ancestor.parent
    return False


def check_balanced_ldev(func_node, body):
    """Check that every exit path in a function balances get_ldev/put_ldev.

    Returns list of ``(return_line, get_line)`` for imbalanced exits.
    Handles Pattern A (negated guard) and Pattern B (positive if-body).
    Skips Pattern C (deferred boolean flag) and ldev_safe functions.
    """
    issues = []
    stmts = [c for c in body.named_children if c.type != "comment"]

    # Skip if no actual get_ldev calls
    if not contains_call(body, GET_LDEV):
        return issues

    # Skip functions with ldev_safe annotation
    if _has_ldev_safe(body):
        return issues

    # Detect Pattern C (deferred flag) — skip these
    ldev_vars = set()
    _collect_ldev_vars(stmts, ldev_vars)
    if ldev_vars:
        return issues
    for stmt in stmts:
        pos_body = _is_positive_get_ldev_if(stmt)
        if pos_body is not None:
            flag_vars = set()
            _collect_ldev_flag_vars(pos_body, flag_vars)
            if flag_vars:
                return issues

    # Compute annotation regions for per-return suppression
    # Both ldev_safe and ldev_ref_transfer suppress balance warnings.
    ldev_safe_regions = []
    _find_ldev_safe_comment_regions(body, ldev_safe_regions)
    _find_annotation_regions(body, ldev_safe_regions, LDEV_REF_TRANSFER_RE)

    # --- Pattern A: if (!get_ldev()) bail; ---
    for stmt in stmts:
        if not _is_negated_get_ldev_if(stmt):
            continue

        get_line = _get_ldev_call_line(stmt)
        guard_end_byte = stmt.end_byte
        consequence = stmt.child_by_field_name("consequence")

        for node in walk_body(body):
            if node.type != "return_statement":
                continue
            if node.start_byte <= guard_end_byte:
                continue
            # Skip returns inside the guard's bail-out consequence
            if (consequence and
                    consequence.start_byte <= node.start_byte <=
                    consequence.end_byte):
                continue
            # Skip returns inside a nested Pattern B body
            if _is_inside_pattern_b(node, body, stmt):
                continue
            # Skip returns annotated with /* ldev_safe: ... */
            if is_in_regions(node.start_byte, ldev_safe_regions):
                continue

            if not _has_preceding_put_ldev(node, body):
                ret_line = node.start_point[0] + 1
                issues.append((ret_line, get_line))

    # --- Pattern B: if (get_ldev()) { body } (standalone only) ---
    has_pattern_a = any(_is_negated_get_ldev_if(s) for s in stmts)
    if not has_pattern_a:
        for stmt in stmts:
            pos_body = _is_positive_get_ldev_if(stmt)
            if pos_body is None:
                continue
            get_line = _get_ldev_call_line(stmt)

            for node in walk_body(pos_body):
                if node.type != "return_statement":
                    continue
                if is_in_regions(node.start_byte, ldev_safe_regions):
                    continue
                if not _has_preceding_put_ldev(node, pos_body):
                    ret_line = node.start_point[0] + 1
                    issues.append((ret_line, get_line))

    return issues


# ---------------------------------------------------------------------------
# Data structures for cross-file analysis
# ---------------------------------------------------------------------------

class FuncInfo:
    __slots__ = ("name", "filepath", "static", "has_get_ldev",
                 "accesses", "calls", "protected_regions",
                 "balance_issues")

    def __init__(self, name, filepath, static):
        self.name = name
        self.filepath = filepath
        self.static = static
        self.has_get_ldev = False
        self.accesses = []       # [(byte_pos, line, col, field)]
        self.calls = []          # [(callee_name, byte_pos)]
        self.protected_regions = []  # [(start_byte, end_byte)]
        self.balance_issues = []  # [(return_line, get_line)]


# ---------------------------------------------------------------------------
# Phase 1: Parse all files
# ---------------------------------------------------------------------------

def parse_all_files(filepaths, parser):
    """Parse all files and return a dict of func_key -> FuncInfo,
    where func_key = (filepath, name) for static, name for non-static."""
    funcs = {}

    for filepath in filepaths:
        if not os.path.isfile(filepath):
            print(f"Warning: {filepath} not found, skipping", file=sys.stderr)
            continue

        with open(filepath, "rb") as f:
            source = f.read()
        tree = parser.parse(source)

        for func_node in find_function_definitions(tree.root_node):
            name = get_function_name(func_node)
            if name is None:
                continue

            body = func_node.child_by_field_name("body")
            if body is None:
                continue

            static = is_static(func_node)
            info = FuncInfo(name, filepath, static)
            type_map = build_type_map(func_node, body)
            info.accesses = find_field_accesses(body, {"ldev", "bitmap"}, type_map)
            info.calls = find_calls(body)
            info.has_get_ldev = (contains_call(body, GET_LDEV)
                                 or _has_ldev_safe(body)
                                 or _has_ldev_ref_transfer_func(body))

            if info.has_get_ldev:
                info.protected_regions = find_protected_regions(body)

            if contains_call(body, GET_LDEV):
                info.balance_issues = check_balanced_ldev(func_node, body)

            # Key: (filepath, name) for static functions, just name otherwise
            key = (filepath, name) if static else name
            funcs[key] = info

    return funcs


# ---------------------------------------------------------------------------
# Phase 2: Build reverse call graph
# ---------------------------------------------------------------------------

def build_reverse_call_graph(funcs):
    """Build mapping: callee_key -> [(caller_key, call_byte_pos), ...]"""
    reverse = defaultdict(list)

    for caller_key, caller_info in funcs.items():
        for callee_name, call_pos, _line in caller_info.calls:
            # Resolve callee: prefer static in same file, else global
            static_key = (caller_info.filepath, callee_name)
            if static_key in funcs:
                callee_key = static_key
            elif callee_name in funcs:
                callee_key = callee_name
            else:
                # Callee not in our analysis (external/kernel function)
                continue
            reverse[callee_key].append((caller_key, call_pos))

    return reverse


# ---------------------------------------------------------------------------
# Phase 3: Bottom-up analysis
# ---------------------------------------------------------------------------

def is_call_protected(caller_info, call_byte_pos):
    """Check if a call at call_byte_pos in caller is within a
    get_ldev/put_ldev bracket."""
    if not caller_info.has_get_ldev:
        return False
    return is_in_regions(call_byte_pos, caller_info.protected_regions)


def analyze(funcs, reverse):
    """Bottom-up analysis. Returns the set of func_keys that access
    ldev/bitmap and are NOT fully protected by callers."""

    # needs_ldev: functions that require ldev to be held by their caller.
    # Initially: functions that directly access ldev/bitmap without own get_ldev,
    # OR functions that have get_ldev/ldev_safe but have accesses outside their
    # protected regions.
    needs_ldev = set()
    # self_unprotected: functions that have their own get_ldev/ldev_safe but
    # still have accesses outside protected regions — report these directly.
    self_unprotected = {}  # key -> [(line, col, field), ...]
    for key, info in funcs.items():
        if not info.accesses:
            continue
        if not info.has_get_ldev:
            needs_ldev.add(key)
        else:
            # Check each access against protected regions
            bad = [(line, col, field)
                   for byte_pos, line, col, field in info.accesses
                   if not is_in_regions(byte_pos, info.protected_regions)]
            if bad:
                self_unprotected[key] = bad

    # Self-unprotected functions have accesses outside their own
    # protected regions that rely on callers holding ldev.
    needs_ldev.update(self_unprotected.keys())

    # Propagate upward: if a needs_ldev function is called outside a
    # get_ldev bracket, the caller also needs_ldev.
    changed = True
    while changed:
        changed = False
        for callee_key in list(needs_ldev):
            for caller_key, call_pos in reverse.get(callee_key, []):
                if caller_key in needs_ldev:
                    continue  # Already known
                caller_info = funcs[caller_key]
                if not is_call_protected(caller_info, call_pos):
                    needs_ldev.add(caller_key)
                    changed = True

    # Now determine which needs_ldev functions are truly unprotected:
    # A function is "covered" if ALL its call sites are either:
    #   (a) in a get_ldev/put_ldev bracket, or
    #   (b) in a caller that is itself in needs_ldev (issue deferred to caller)
    # A function with NO call sites is "uncovered" (entry point / callback).
    uncovered = set()
    for key in needs_ldev:
        call_sites = reverse.get(key, [])
        if not call_sites:
            # No callers found — entry point, callback, or exported function.
            # Can't verify protection.
            uncovered.add(key)
            continue

        for caller_key, call_pos in call_sites:
            caller_info = funcs[caller_key]
            if is_call_protected(caller_info, call_pos):
                continue  # This call site is fine
            if caller_key in needs_ldev:
                continue  # Deferred — caller will be checked
            # Caller is NOT in needs_ldev and call is NOT protected → bug
            uncovered.add(key)
            break

    return uncovered, needs_ldev, self_unprotected


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _resolve_callee(caller_info, callee_name, funcs):
    """Resolve a callee name to its func_key."""
    static_key = (caller_info.filepath, callee_name)
    if static_key in funcs:
        return static_key
    if callee_name in funcs:
        return callee_name
    return None


def report_results(uncovered, needs_ldev, funcs, self_unprotected):
    """Print call chains for uncovered functions, tracing down to the
    direct ldev/bitmap accesses."""

    # Collect (filepath, line, name, key) for sorting
    entries = []
    for key in uncovered:
        info = funcs[key]
        # Use the function's first access line, or first unprotected
        # needs_ldev call line, for sorting purposes.
        sort_line = 0
        if info.accesses and not info.has_get_ldev:
            sort_line = info.accesses[0][1]
        elif key in self_unprotected:
            sort_line = self_unprotected[key][0][0]
        else:
            for _, call_pos, call_line in info.calls:
                callee_key = _resolve_callee(info, _, funcs)
                if callee_key and callee_key in needs_ldev:
                    sort_line = call_line
                    break
        entries.append((info.filepath, sort_line, info.name, key))

    entries.sort()

    visited = set()
    for _, _, _, key in entries:
        _print_chain(key, funcs, needs_ldev, depth=0, visited=visited,
                     self_unprotected=self_unprotected)
        print()


def _print_chain(key, funcs, needs_ldev, depth, visited,
                 self_unprotected=None):
    """Recursively print the call chain from an uncovered function
    down to the leaf functions that directly access ldev/bitmap."""
    if key in visited:
        return
    visited.add(key)
    info = funcs[key]
    indent = "  " * depth

    # Leaf: direct accessor without own get_ldev
    if info.accesses and not info.has_get_ldev:
        for _, line, col, field in info.accesses:
            print(f"{indent}** {info.name}() accesses ->{field}"
                  f"  {info.filepath}:{line}")
        return

    # Leaf: has own get_ldev but accesses outside protected region
    if self_unprotected and key in self_unprotected:
        for line, col, field in self_unprotected[key]:
            print(f"{indent}** {info.name}() accesses ->{field} outside its "
                  f"own protected region  {info.filepath}:{line}")
        return

    # Interior: show unprotected calls to needs_ldev functions
    for callee_name, call_pos, call_line in info.calls:
        callee_key = _resolve_callee(info, callee_name, funcs)
        if callee_key is None or callee_key not in needs_ldev:
            continue
        if is_call_protected(info, call_pos):
            continue
        callee_info = funcs[callee_key]
        print(f"{indent}{info.name}() calls {callee_info.name}()"
              f"  {info.filepath}:{call_line}")
        _print_chain(callee_key, funcs, needs_ldev, depth + 1, visited,
                     self_unprotected)


def report_balance_issues(funcs):
    """Print warnings for functions with imbalanced get_ldev/put_ldev."""
    entries = []
    for key, info in funcs.items():
        for ret_line, get_line in info.balance_issues:
            entries.append((info.filepath, ret_line, info.name, get_line))

    entries.sort()
    for filepath, ret_line, name, get_line in entries:
        print(f"!! {name}() may leak ldev ref: return without "
              f"put_ldev()  {filepath}:{ret_line}")
        print(f"   get_ldev() at line {get_line}, "
              f"no put_ldev() before return at line {ret_line}")
    if entries:
        print()


# ---------------------------------------------------------------------------
# Verify mode: show all call paths with their ldev protection
# ---------------------------------------------------------------------------

def _find_call_line(caller_info, call_pos):
    """Look up the source line of a call from its byte position."""
    for _, cpos, cline in caller_info.calls:
        if cpos == call_pos:
            return cline
    return 0


def _print_transitive_accesses(key, funcs, needs_ldev, depth, visited,
                               self_unprotected=None):
    """Trace downward from *key* to show what ldev/bitmap accesses it
    transitively reaches.  Similar to _print_chain but used for -v output."""
    if key in visited:
        return
    visited.add(key)
    info = funcs[key]
    indent = "  " * depth

    # Leaf: direct accessor without own get_ldev
    if info.accesses and not info.has_get_ldev:
        for _, line, col, field in info.accesses:
            print(f"{indent}** {info.name}() accesses ->{field}"
                  f"  {info.filepath}:{line}")
        return

    # Leaf: has own get_ldev but accesses outside protected region
    if self_unprotected and key in self_unprotected:
        for line, col, field in self_unprotected[key]:
            print(f"{indent}** {info.name}() accesses ->{field} outside its "
                  f"own protected region  {info.filepath}:{line}")
        return

    # Interior: show calls to needs_ldev functions
    for callee_name, call_pos, call_line in info.calls:
        callee_key = _resolve_callee(info, callee_name, funcs)
        if callee_key is None or callee_key not in needs_ldev:
            continue
        if is_call_protected(info, call_pos):
            continue
        callee_info = funcs[callee_key]
        print(f"{indent}{info.name}() calls {callee_info.name}()"
              f"  {info.filepath}:{call_line}")
        _print_transitive_accesses(callee_key, funcs, needs_ldev,
                                   depth + 1, visited, self_unprotected)


def verify_function(func_name, funcs, reverse, needs_ldev,
                    self_unprotected):
    """Show all call paths to *func_name* and where each acquires
    ldev protection.  Exits with 1 if any path is unprotected."""

    candidates = [(k, info) for k, info in funcs.items()
                  if info.name == func_name]
    if not candidates:
        print(f"Function {func_name}() not found", file=sys.stderr)
        sys.exit(1)

    any_unprotected = False
    for key, info in candidates:
        # Check direct accesses
        has_direct = bool(info.accesses)
        # Check transitive: calls needs_ldev functions outside own regions
        has_transitive = key in needs_ldev and not has_direct

        if not has_direct and not has_transitive:
            print(f"{info.name}() does not access ->ldev or ->bitmap"
                  f"  {info.filepath}")
            continue

        # Show what it accesses (directly and transitively)
        if has_direct:
            for _, line, col, field in info.accesses:
                self_ok = (info.has_get_ldev and
                           is_in_regions(_, info.protected_regions))
                tag = "  [self-protected]" if self_ok else ""
                print(f"{info.name}() accesses ->{field}"
                      f"  {info.filepath}:{line}{tag}")

        # Show transitive access chain
        _print_transitive_accesses(key, funcs, needs_ldev, 0, set(),
                                   self_unprotected)

        # Any access outside own regions (direct or transitive)?
        direct_needs_caller = any(
            not (info.has_get_ldev and
                 is_in_regions(bp, info.protected_regions))
            for bp, _, _, _ in info.accesses) if has_direct else False

        if not direct_needs_caller and not has_transitive:
            print("All accesses self-protected.\n")
            continue

        print("\nCaller protection:")
        bad = _verify_callers(key, funcs, reverse, depth=1, on_stack={key})
        if bad:
            any_unprotected = True
        print()

    sys.exit(1 if any_unprotected else 0)


def _verify_callers(key, funcs, reverse, depth, on_stack):
    """Trace callers upward.  Returns True if any path is unprotected."""
    info = funcs[key]
    indent = "  " * depth
    call_sites = reverse.get(key, [])

    if not call_sites:
        # Entry point / callback — no callers to verify
        if info.has_get_ldev:
            print(f"{indent}{info.name}()  {info.filepath}"
                  f"  [own get_ldev]")
            return False
        print(f"{indent}{info.name}()  {info.filepath}"
              f"  [UNPROTECTED entry point]")
        return True

    any_bad = False
    for caller_key, call_pos in call_sites:
        caller_info = funcs[caller_key]
        call_line = _find_call_line(caller_info, call_pos)

        if is_call_protected(caller_info, call_pos):
            print(f"{indent}{caller_info.name}() calls {info.name}()"
                  f"  {caller_info.filepath}:{call_line}  [protected]")
        else:
            print(f"{indent}{caller_info.name}() calls {info.name}()"
                  f"  {caller_info.filepath}:{call_line}")
            if caller_key in on_stack:
                continue
            on_stack.add(caller_key)
            if _verify_callers(caller_key, funcs, reverse,
                               depth + 1, on_stack):
                any_bad = True
            on_stack.discard(caller_key)

    return any_bad


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]
    verify_func = None

    if len(args) >= 1 and args[0] == "-v":
        if len(args) < 3:
            print(f"Usage: {sys.argv[0]} -v <func_name> <file.c> [...]",
                  file=sys.stderr)
            sys.exit(1)
        verify_func = args[1]
        args = args[2:]

    if not args:
        print(f"Usage: {sys.argv[0]} [-v func_name] <file.c> [file2.c ...]",
              file=sys.stderr)
        sys.exit(1)

    parser = make_parser()
    filepaths = [f for f in args if os.path.isfile(f)]

    funcs = parse_all_files(filepaths, parser)
    reverse = build_reverse_call_graph(funcs)
    uncovered, needs_ldev, self_unprotected = analyze(funcs, reverse)

    if verify_func:
        verify_function(verify_func, funcs, reverse, needs_ldev,
                        self_unprotected)
        return
    report_results(uncovered, needs_ldev, funcs, self_unprotected)
    report_balance_issues(funcs)

    has_findings = bool(uncovered) or any(
        info.balance_issues for info in funcs.values())
    sys.exit(1 if has_findings else 0)


if __name__ == "__main__":
    main()
