@@
struct ib_device dev;
expression D, A, U;
@@
- dev.ops.query_device(D, A, U)
+ dev.query_device(D, A, U)

@@
struct ib_device *dev;
expression D, A, U;
@@
- dev->ops.query_device(D, A, U)
+ dev->query_device(D, A, U)


@@
struct ib_device dev;
expression D, P, F, G;
@@
- dev.ops.query_gid(D, P, F, G)
+ dev.query_gid(D, P, F, G)

@@
struct ib_device *dev;
expression D, P, F, G;
@@
- dev->ops.query_gid(D, P, F, G)
+ dev->query_gid(D, P, F, G)
