@ find_idr_is_empty @
struct idr *idr;
@@
 idr_is_empty(idr)


@script:python gen_idr_is_empty@
idr << find_idr_is_empty.idr;
x;
@@
coccinelle.x = "({ int id = 0; idr_get_next(" + idr + ", &id) == NULL; })"

@@
struct idr *find_idr_is_empty.idr;
identifier gen_idr_is_empty.x;
@@
- idr_is_empty(idr)
+ x
