@@
@@
- #include <linux/tls.h>

@@
@@
- #include <net/handshake.h>

@@
@@
- #include <net/tls.h>

@@
@@
- #include <net/tls_prot.h>

@@
identifier msg;
@@
- if (msg.msg_controllen != ...) { ... }

@@
typedef gfp_t;
@@
- typedef int (*tls_hello_func)(const struct tls_handshake_args *, gfp_t);

@@
@@
- struct tls_handshake_wait { ... };

@@
@@
- static void tls_handshake_done(...) { ... }

@@
@@
- static int tls_init_hello(...) { ... }

@@
@@
- static int tls_wait_hello(...) { ... }

@@
expression s;
@@
- tls_handshake_cancel(s);

@@
@@
  tls_key_lookup(...) {
- 	...
+ 	return ERR_CAST(-EINVAL);
  }

@@
symbol tls;
@@
  if (tls) {
- 	...
+ 	err = -ENOTSUPP;
+ 	goto out;
  }
