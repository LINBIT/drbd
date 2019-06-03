@ find_crypto_hash_h @
@@
 #include <crypto/hash.h>

@ add_crypto_hash_h depends on !find_crypto_hash_h @
@@
 #include <...>
+ #include <crypto/hash.h>
