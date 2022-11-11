/* { "version": "v5.8", "commit": "480aeb9639d6a077c611b303a22f9b1e5937d081", "comment": "tcp: add tcp_sock_set_keepcnt", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu May 28 07:12:25 2020 +0200" } */

/* ...and there were the commits:
d41ecaac903c9f4658a71d4e7a708673cfb5abba tcp: add tcp_sock_set_keepintvl
...seconds later.
*/

#include <linux/tcp.h>

void foo(struct socket *sock)
{
	tcp_sock_set_keepcnt(sock->sk, 0);
}
