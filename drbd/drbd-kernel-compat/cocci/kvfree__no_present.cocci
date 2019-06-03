@ find_linux_mm_h @
@@
 #include <linux/mm.h>

@replace_kvfree@
type T;
T *addr;
@@
// NOTE: The curly braces around the if are necessary to work around a
// coccinelle bug where the indentation gets messed up for code like the
// following:
//
// if (x)
//    kvfree(addr);
//
- kvfree(addr);
+ if (is_vmalloc_addr(addr)) {
+	vfree(addr);
+ } else {
+	kfree(addr);
+ }

@ add_linux_mm_h depends on !find_linux_mm_h && ever replace_kvfree @
@@
 #include <...>
+ #include <linux/mm.h>
