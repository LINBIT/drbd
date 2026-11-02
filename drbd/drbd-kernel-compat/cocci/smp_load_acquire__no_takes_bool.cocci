@@
bool E;
expression V;
@@
-smp_store_release(&E, V);
+smp_mb();
+WRITE_ONCE(E, V);

@@
bool E;
expression X;
@@
-X = smp_load_acquire(&E);
+X = READ_ONCE(E);
+smp_mb();
