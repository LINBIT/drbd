@@
expression tfm;
@@
- if (crypto->verify_tfm && (crypto_shash_get_flags(tfm) & CRYPTO_TFM_NEED_KEY))
+ if (crypto->verify_tfm)
{
+	/* HACK: try to set a dummy key. if it succeeds, that's bad: we only want algorithms that don't support keys */
+	u8 dummy_key[] = {'a'};
+	int setkey_res = crypto_shash_setkey(crypto->verify_tfm, dummy_key, 1);
+	if (setkey_res != -ENOSYS) {
...
+	}
}
