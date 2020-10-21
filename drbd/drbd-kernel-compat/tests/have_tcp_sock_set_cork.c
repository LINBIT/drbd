/* { "version": "v5.8", "commit": "db10538a4b997a77a1fd561adaaa58afc7dcfa2f", "comment": "In 5.8 kernel_setsockopt with TCP_CORK was replaced by tcp_sock_set_cork", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu May 28 07:12:18 2020 +0200" } */

#include <linux/tcp.h>

void foo(struct socket *sock)
{
	tcp_sock_set_cork(sock->sk, true);
}
