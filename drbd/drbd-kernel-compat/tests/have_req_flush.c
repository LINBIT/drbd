/* { "version": "v2.6.36", "commit": "8749534fe6826596b71bc409c872b047a8e2755b", "comment": "REQ_FLUSH got introduced in 2.6.36", "author": "FUJITA Tomonori <fujita.tomonori@lab.ntt.co.jp>", "date": "Sat Jul 3 17:45:32 2010 +0900" } */

#include <linux/bio.h>

int dummy = REQ_FLUSH;
