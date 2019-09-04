/* {"version": "5.3-rc5", "commit": "33da8e7c814f77310250bb54a9db36a44c5de784", "comment": "allow_kernel_signal was added to only allow signals from other kernel threads, not from userspace", "author": "Eric W. Biederman <ebiederm@xmission.com>", "date": "Fri Aug 16 12:33:54 2019 -0500"} */
#include <linux/signal.h>

void dummy(int sig)
{
	allow_kernel_signal(sig);
}
