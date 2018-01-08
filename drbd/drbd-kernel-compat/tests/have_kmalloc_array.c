commit a99e525b7341df6d84977e9bb47959311c94cfad
Author: Lars Ellenberg <lars.ellenberg@linbit.com>
Date:   Wed Aug 16 11:10:28 2017 +0200

    compat: kmalloc_array()

diff --git a/compat/tests/have_kmalloc_array.c b/compat/tests/have_kmalloc_array.c
new file mode 100644
index 0000000..288f928
--- /dev/null
+++ b/compat/tests/have_kmalloc_array.c
@@ -0,0 +1,6 @@
+#include <linux/slab.h>
+
+void test(void)
+{
+	kmalloc_array(0, 0, 0);
+}
