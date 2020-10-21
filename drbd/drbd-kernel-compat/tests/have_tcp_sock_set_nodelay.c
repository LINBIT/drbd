/* { "version": "v5.8", "commit": "12abc5ee7873a085cc280240822b8ac53c86fecd", "comment": "In 5.8 kernel_setsockopt with TCP_NODELAY was replaced by tcp_sock_set_nodelay", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu May 28 07:12:19 2020 +0200" } */

#include <linux/tcp.h>

void foo(struct socket *sock)
{
	tcp_sock_set_nodelay(sock->sk);
}
