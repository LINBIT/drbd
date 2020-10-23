/* { "version": "v5.9-rc7", "commit": "c381b07941adc2274ce552daf86c94701c5e265a", "comment": "In v5.9-rc7 sendpage_ok() was introduced", "author": "Coly Li <colyli@suse.de>", "date": "Fri Oct 2 16:27:28 2020 +0800" } */

#include <linux/net.h>

void foo(struct page *page)
{
	sendpage_ok(page);
}
