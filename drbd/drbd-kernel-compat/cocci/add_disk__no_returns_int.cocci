@ remove_add_disk_return @
identifier e;
identifier d;
identifier label;
@@
enum drbd_ret_code e = ...;
...
- e =
add_disk(d);
- if (e)
-	goto label;

@@
identifier remove_add_disk_return.label;
identifier label_after;
@@
-label:
-...
label_after:
