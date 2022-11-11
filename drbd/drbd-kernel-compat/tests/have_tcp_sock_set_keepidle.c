/* { "version": "v5.8", "commit": "71c48eb81c9ecb6fed49dc33e7c9b621fdcb7bf8", "comment": "tcp: add tcp_sock_set_keepidle", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu May 28 07:12:23 2020 +0200" } */

#include <linux/tcp.h>

void foo(struct socket *sock)
{
	tcp_sock_set_keepidle(sock->sk, 0);
}

