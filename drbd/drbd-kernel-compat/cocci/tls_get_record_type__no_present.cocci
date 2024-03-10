@@
@@
- #include <net/tls_prot.h>

@@
typedef u8;
@@
+ #define TLS_RECORD_TYPE_ALERT	0x15
+ #define TLS_RECORD_TYPE_DATA	0x17
+ #define TLS_ALERT_LEVEL_FATAL	2
+ #define TLS_GET_RECORD_TYPE	2
+
+ /**
+  * tls_get_record_type - Look for TLS RECORD_TYPE information
+  * @sk: socket (for IP address information)
+  * @cmsg: incoming message to be parsed
+  *
+  * Returns zero or a TLS_RECORD_TYPE value.
+  */
+ static u8 tls_get_record_type(const struct sock *sk, const struct cmsghdr *cmsg)
+ {
+ 	if (cmsg->cmsg_level != SOL_TLS)
+ 		return 0;
+ 	if (cmsg->cmsg_type != TLS_GET_RECORD_TYPE)
+ 		return 0;
+
+ 	return *((u8 *)CMSG_DATA(cmsg));
+ }
+
+ /**
+  * tls_alert_recv - Parse TLS Alert messages
+  * @sk: socket (for IP address information)
+  * @msg: incoming message to be parsed
+  * @level: OUT - TLS AlertLevel value
+  * @description: OUT - TLS AlertDescription value
+  *
+  */
+ static void tls_alert_recv(const struct sock *sk, const struct msghdr *msg, u8 *level, u8 *description)
+ {
+ 	const struct kvec *iov = msg->msg_iter.kvec;
+ 	u8 *data = iov->iov_base;
+
+ 	*level = data[0];
+ 	*description = data[1];
+ }
+
  dtt_recv_short(...)
  { ... }
