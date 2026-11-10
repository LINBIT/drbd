/* { "version": "v7.4-rc1", "commit": "6ba48a271bdb9c3e106314936ee202f7f249a3db", "comment": "sk_set_nospace() sets SOCK_NOSPACE and the mirror of it that TCP keeps in struct tcp_sock", "author": "Eric Dumazet <edumazet@kernel.org>", "date": "Tue Sep 29 07:17:36 2026 +0000" } */

#include <net/sock.h>

void foo(struct sock *sk)
{
	sk_set_nospace(sk);
}
