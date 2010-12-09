#include <linux/kernel.h>
#include <linux/connector.h>

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

void dummy(void)
{
	void (*cb) (struct cn_msg *, struct netlink_skb_parms *) = NULL;
	struct cn_callback_data ccb;
	BUILD_BUG_ON(!(__same_type(ccb.callback, cb)));
}
