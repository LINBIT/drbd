@ pfn_t_matched @
identifier p;
@@
- unsigned long
+ pfn_t
p;
...
dax_direct_access(..., &p)

@ depends on ever pfn_t_matched @
@@
#include <...>
+ #include <linux/pfn_t.h>
