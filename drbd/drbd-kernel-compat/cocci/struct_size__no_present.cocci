@ replace_struct_size @
identifier p; // pointer to the structure
identifier m; // name of the array member
expression n; // number of elements in the array
@@
- struct_size(p, m, n)
+ sizeof(*p) + sizeof(*p->m) * n

@ depends on replace_struct_size @
@@
- #include <linux/overflow.h>
