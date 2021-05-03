@@
identifier h;
@@
- return h && (crypto_shash_get_flags(h) & CRYPTO_TFM_NEED_KEY);
+ /*
+  * On kernels before 4.15, there is no way to check whether or not an algorithm
+  * requires a key. Allow all algorithms, possibly leading to BUGs if they are
+  * used later.
+  */
+ return false;
