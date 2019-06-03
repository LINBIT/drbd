@@
expression req;
@@
- ahash_request_zero(req);
+ memset(req, 0, sizeof(*req) + crypto_ahash_reqsize(crypto_ahash_reqtfm(req)));
+ #ifdef barrier_data
+	barrier_data(req);
+ #else
+	barrier();
+ #endif

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
