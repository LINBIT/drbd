@@
expression desc;
@@
- shash_desc_zero(desc);
+ memset(desc, 0, sizeof(*desc) + crypto_shash_descsize(desc->tfm));
+ #ifdef barrier_data
+	barrier_data(desc);
+ #else
+	barrier();
+ #endif
