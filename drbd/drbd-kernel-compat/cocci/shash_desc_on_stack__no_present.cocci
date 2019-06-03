@ find_shash_desc_on_stack @
identifier nam;
expression shash;
fresh identifier arr = "__" ## nam ## "_desc";
@@
- SHASH_DESC_ON_STACK(nam, shash);
// NOTE: We cannot use the CRYPTO_MINALIGN_ATTR macro here because coccinelle
// trips on it.
+ char arr[sizeof(struct shash_desc) + crypto_shash_descsize(shash)] __attribute__((__aligned__(CRYPTO_MINALIGN)));
+ struct shash_desc *nam = (struct shash_desc *)arr;
