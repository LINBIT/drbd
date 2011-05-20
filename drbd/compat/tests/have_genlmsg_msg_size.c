#include <net/genetlink.h>

void f(void)
{
	int dummy;

	dummy = genlmsg_msg_size(0);
	dummy = genlmsg_total_size(0);
}
