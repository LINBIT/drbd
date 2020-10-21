/* { "version": "v5.8", "commit": "ddd061b8daed3ce0c01109a69c9a2a9f9669f01a", "comment": "In 5.8 kernel_setsockopt with TCP_QUICKACK was replaced by tcp_sock_set_quickack", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu May 28 07:12:20 2020 +0200" } */

#include <linux/tcp.h>

void foo(struct socket *sock)
{
	tcp_sock_set_quickack(sock->sk, 2);
}
