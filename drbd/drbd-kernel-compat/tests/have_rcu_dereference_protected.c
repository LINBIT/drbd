#include <linux/rcupdate.h>
#include <linux/mutex.h>

struct mutex *dummy(void)
{
	struct mutex m;
	struct mutex *b = NULL;

	return rcu_dereference_protected(b, lockdep_is_held(&m));
}
