/* { "version": "v6.0-rc1", "commit": "342a72a334073f163da924b69c3d3fb4685eb33a", "comment": "blk_opf_t was introduced", "author": "Bart Van Assche <bvanassche@acm.org>", "date": "Thu Jul 14 11:06:31 2022 -0700" } */

#include <linux/blk_types.h>

blk_opf_t foo = REQ_OP_WRITE;
