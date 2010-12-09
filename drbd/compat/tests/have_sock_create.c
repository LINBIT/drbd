#include <linux/net.h>

#ifndef sock_create_kern
void *p = sock_create_kern;
#endif
