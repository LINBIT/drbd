// NLA_POLICY_MAX_LEN was added in v6.13. Coccinelle cannot replace a macro
// call with a struct initializer without array context, so we match the
// full array initializer entry.
@@
expression LEN, IDX;
type T;
identifier x;
@@
T x[...] = {
    ...,
    [IDX] =
-   NLA_POLICY_MAX_LEN(LEN)
+   { .type = NLA_BINARY, .len = LEN }
    , ...
};
