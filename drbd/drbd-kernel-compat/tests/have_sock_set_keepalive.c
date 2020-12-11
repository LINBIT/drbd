/* { "version": "v5.8", "commit": "ce3d9544cecacd40389c399d2b7ca31acc533b70", "comment": "kernel_setsockopt with SO_KEEPALIVE was replaced by sock_set_keepalive", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu May 28 07:12:15 2020 +0200" } */

#include <linux/tcp.h>

void foo(struct socket *sock)
{
	sock_set_keepalive(sock->sk);
}
