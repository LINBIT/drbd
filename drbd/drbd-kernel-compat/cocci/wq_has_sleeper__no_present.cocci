@@
expression wq;
statement S;
@@
+smp_mb();
 if (
-wq_has_sleeper(wq)
+waitqueue_active(wq)
 ) S
