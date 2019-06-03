@ find_ahash_request_on_stack @
identifier nam;
identifier ahash;
fresh identifier arr = "__" ## nam ## "_desc";
@@
- AHASH_REQUEST_ON_STACK(nam, ahash);
// NOTE: We cannot use the CRYPTO_MINALIGN_ATTR macro here because coccinelle
// trips on it.
+ char arr[sizeof(struct ahash_request) + crypto_ahash_reqsize(ahash)] __attribute__((__aligned__(CRYPTO_MINALIGN)));
+ struct ahash_request *nam = (void *)arr;
