@ find_linux_mm_h @
@@
 #include <linux/mm.h>

@replace_kvfree@
expression e;
type T;
T *addr;
@@
// NOTE: Special case for single statement necessary to avoid a "dangling" else.
- if (e)
- 	kvfree(addr);
+ if (e) {
+ 	if (is_vmalloc_addr(addr))
+		vfree(addr);
+ 	else
+		kfree(addr);
+ }

@replace_kvfree2@
type T;
T *addr;
@@
- kvfree(addr);
+ if (is_vmalloc_addr(addr))
+ 	vfree(addr);
+ else
+ 	kfree(addr);


@ add_linux_mm_h depends on !find_linux_mm_h && ( ever replace_kvfree || ever replace_kvfree2 ) @
@@
 #include <...>
+ #include <linux/mm.h>
