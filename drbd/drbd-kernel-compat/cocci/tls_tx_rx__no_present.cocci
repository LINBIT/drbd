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
expression new_key, flags, perms;
key_ref_t ref;
@@
  tls_key_lookup(...) {
  <...
- ref = lookup_user_key(new_key, flags, perms)
+ ref = ERR_PTR(-ENOKEY);
  ...>
  }

@@
symbol tls;
@@
  if (tls) {
- 	...
+ 	err = -ENOTSUPP;
+ 	goto out;
  }

@@
identifier transport, new_net_conf, ret;
@@
  dtt_net_conf_change(struct drbd_transport *transport, struct net_conf *new_net_conf) {
  	...
  	int ret;
  	...
  	rcu_read_unlock();

+ 	if (new_net_conf->tls) {
+ 		tr_warn(transport, "kernel does not support kTLS\n");
+ 		ret = -EINVAL;
+ 		goto end;
+ 	}
  	...
  }
