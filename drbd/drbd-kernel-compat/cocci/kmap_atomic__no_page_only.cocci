// This is a pretty complex script, so I'll try to walk through it...
//
// Basically, the objective is to "re-introduce" the km_type parameter to
// k[un]map_atomic(). The issue is that the whole concept of this parameter
// got dropped. By simply removing it in the main code we would lose
// semantic information which the original author of the code manually thought
// of; so we can't really restore this through a coccinelle patch.
//
// Our solution to this is a "tag" that can be put after the argument list of
// any function. This tag consists of a comment of the following form:
//	/* kmap compat: KM_USER0 */
//
// When such a tag is found on a function, all calls to kmap_atomic (and others)
// within this function are rewritten to contain the specified KM_ constant
// as their km_type.

// This rule just finds a function with a comment after the argument list.
@ find_kmap_tagged_function @
comments tag;
identifier fn;
@@
fn(...)@tag {
...
}

// Here we try to parse the "kmap compat: KM_FOO" part to extract "KM_FOO".
// If we don't find it (which most likely means there's no tag there), we just
// return "km_type", assuming that there's a variable called "km_type" in scope.
// This is kind of janky, but honestly I'm not really sure what else to do in
// this case, and at least it yields a halfway sensible compiler error when it's
// wrong.
@ script:python parse_kmap_tag @
tag << find_kmap_tagged_function.tag;
km;
@@
import re
match = re.search(r'^\/\*\skmap compat: (.*)\s\*\/$', tag[0].after)
if match:
    coccinelle.km = match.group(1)
else:
    coccinelle.km = 'km_type'

// Actually replace calls to relevant functions inside the tagged functions we
// found above.
@@
identifier find_kmap_tagged_function.fn;
identifier parse_kmap_tag.km;
@@
fn(...) {
<...
(
___bm_op
|
____bm_op
|
bm_map
|
bm_unmap
|
kmap_atomic
|
kunmap_atomic
)
 (...
+    , km
         )
...>
}


// There's some macros defined for debugging (#ifdef BITMAP_DEBUG), and we need
// to change the definition of those as well (and the calls inside them)
@@
identifier device, bitmap_index, start, end, op, buffer;
@@
(
-#define ___bm_op(device, bitmap_index, start, end, op, buffer)
+#define ___bm_op(device, bitmap_index, start, end, op, buffer, km_type)
|
-____bm_op(device, bitmap_index, start, end, op, buffer)
+____bm_op(device, bitmap_index, start, end, op, buffer, km_type)
)

// Rewrite the function definitions for all our own functions that used to have
// a km_type parameter.
@@
identifier d, i, t, e, o, b;
@@
-____bm_op(struct drbd_device *d, unsigned int i, unsigned long t, unsigned long e, enum bitmap_operations o, __le32 *b)
+____bm_op(struct drbd_device *d, unsigned int i, unsigned long t, unsigned long e, enum bitmap_operations o, __le32 *b, enum km_type km_type)
{ ... }

@@
identifier b, p;
@@
-bm_map(struct drbd_bitmap *b, unsigned int p)
+bm_map(struct drbd_bitmap *b, unsigned int p, enum km_type km_type)
{ ... }

@@
identifier b, a;
@@
-bm_unmap(struct drbd_bitmap *b, void *a)
+bm_unmap(struct drbd_bitmap *b, void *a, enum km_type km_type)
{ ... }

// Finally, in all functions with a km_type argument, rewrite all relevant
// function calls to pass on that parameter.
@@
identifier fn, km;
expression p, b, pa, a;
@@
fn(..., enum km_type km)
{
<...
(
-kmap_atomic(p)
+kmap_atomic(p, km)
|
-kunmap_atomic(p)
+kunmap_atomic(p, km)
|
-bm_map(b, pa)
+bm_map(b, pa, km)
|
-bm_unmap(b, a)
+bm_unmap(b, a, km)
)
...>
}
