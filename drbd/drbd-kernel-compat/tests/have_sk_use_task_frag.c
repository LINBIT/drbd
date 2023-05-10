/* { "version": "v6.2-rc1", "commit": "fb87bd47516d9a26b6d549231aa743b20fd4a569", "comment": "the sk_use_task_frag field was added", "author": "Guillaume Nault <gnault@redhat.com>", "date": "Fri Dec 16 07:45:26 2022 -0500" } */

#include <net/sock.h>

bool foo(struct sock *s)
{
	return s->sk_use_task_frag;
}
