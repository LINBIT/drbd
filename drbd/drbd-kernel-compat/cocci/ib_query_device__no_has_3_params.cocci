@@
struct ib_device dev;
expression D, A;
identifier fn, U;
@@
fn(...)
{
...
- struct ib_udata U = {.outlen = 0, .inlen = 0};
...
- dev.query_device(D, A, &U)
+ dev.query_device(D, A)
...
}

@@
struct ib_device *dev;
expression D, A;
identifier fn, U;
@@
fn(...)
{
...
- struct ib_udata U = {.outlen = 0, .inlen = 0};
...
- dev->query_device(D, A, &U)
+ dev->query_device(D, A)
...
}
