#include <linux/bio.h>

/* Introduced by mainline commit d62e26b3ffd2, available since v4.14 */
void foo(struct request_queue *q)
{
	generic_start_io_acct(q, WRITE, 0, (struct hd_struct *) NULL);
}
