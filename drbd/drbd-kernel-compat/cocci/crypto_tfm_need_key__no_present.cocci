@@
identifier h;
@@
- return h && (crypto_shash_get_flags(h) & CRYPTO_TFM_NEED_KEY);
+ if (h) {
+	/* HACK: try to set a dummy key. if it succeeds, that's bad: we only want algorithms that don't support keys */
+	u8 dummy_key[] = {'a'};
+	return crypto_shash_setkey(h, dummy_key, 1) != -ENOSYS;
+ }
+ return false;
