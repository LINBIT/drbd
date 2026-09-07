"""
Common tree-sitter based C analysis infrastructure for the static
checkers in checks/ (check_ldev_access.py, check_lock_order.py).

Provides:
 - parsing and AST walking helpers that know about tree-sitter's
   misparses of kernel macro constructs
 - function definition extraction (name, static, body)
 - a call finder that also resolves function references passed as
   arguments (``&func``) and via local function pointer variables
 - type maps (variable name -> struct tag) for parameters and locals
 - annotation comment regions and byte-range region queries
 - a reverse call graph with static-function-aware callee resolution

It requires the tree-sitter parser for C. E.g.:
pip install tree_sitter
pip install tree_sitter_c
"""

import sys
import os
from collections import defaultdict

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

C_LANG = Language(tsc.language())


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


def iter_function_definitions(filepaths, parser):
    """Parse *filepaths* and yield (filepath, func_node, name, body, static)
    for every function definition with a resolvable name and a body."""
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

            yield filepath, func_node, name, body, is_static(func_node)


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


def extract_declarator_name(decl):
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
                        name = extract_declarator_name(pdecl)
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
                name = extract_declarator_name(child)
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


def find_field_accesses(body, field_names, type_map, struct_tag):
    """Find all ``->field`` accesses on pointers to ``struct struct_tag``.

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
        if type_map.get(text(arg)) != struct_tag:
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
# Annotation comments and byte-range regions
# ---------------------------------------------------------------------------

def find_annotation_regions(body, regions, annotation):
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


def is_in_regions(byte_pos, regions):
    return any(start <= byte_pos <= end for start, end in regions)


# ---------------------------------------------------------------------------
# Call graph
# ---------------------------------------------------------------------------

def build_reverse_call_graph(funcs):
    """Build mapping: callee_key -> [(caller_key, call_byte_pos), ...]

    *funcs* maps func_key -> info objects with ``filepath`` and ``calls``
    attributes, where func_key is (filepath, name) for static functions
    and the plain name otherwise."""
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


def resolve_callee(caller_info, callee_name, funcs):
    """Resolve a callee name to its func_key."""
    static_key = (caller_info.filepath, callee_name)
    if static_key in funcs:
        return static_key
    if callee_name in funcs:
        return callee_name
    return None
