/* { "version": "v6.5-rc1", "commit": "dc97391e661009eab46783030d2404c9b6e6f2e7", "comment": "sock: Remove ->sendpage*() in favour of sendmsg(MSG_SPLICE_PAGES)", "author": "David Howells <dhowells@redhat.com>", "date": "Fri Jun 23 23:55:12 2023 +0100" } */
#include <linux/net.h>

int foo(void)
{
	return MSG_SPLICE_PAGES;
}
