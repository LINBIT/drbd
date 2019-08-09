@@
struct ib_device dev;
expression D, A, U;
@@
- dev.query_device(D, A, U)
+ dev.query_device(D, A)

@@
struct ib_device *dev;
expression D, A, U;
@@
- dev->query_device(D, A, U)
+ dev->query_device(D, A)
