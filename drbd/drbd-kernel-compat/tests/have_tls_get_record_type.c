/* { "version": "v6.6-rc1", "commit": "39d0e38dcced8d4da92cd11f3ff618bacc42d8a9", "comment": "net/handshake: Add helpers for parsing incoming TLS Alerts", "author": "Chuck Lever <chuck.lever@oracle.com>", "date": "Thu Jul 27 13:37:10 2023 -0400" } */
#include <net/tls.h>
#include <net/handshake.h>

u8 foo(struct sock *sk, struct cmsghdr *cmsg)
{
	return tls_get_record_type(sk, cmsg);
}
