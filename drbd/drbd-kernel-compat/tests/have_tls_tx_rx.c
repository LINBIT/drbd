/* { "version": "v4.17-rc1", "commit": "c46234ebb4d1eee5e09819f49169e51cfc6eb909", "comment": "tls: RX path for ktls", "author": "Dave Watson <davejwatson@fb.com>", "date": "Thu Mar 22 10:10:35 2018 -0700" } */
#include <linux/kconfig.h>
#include <net/tls.h>

#if !IS_ENABLED(CONFIG_TLS)
# error "TLS module not enabled"
#endif

int foo(void)
{
	return TLS_TX;
}

int bar(void)
{
	return TLS_RX;
}
