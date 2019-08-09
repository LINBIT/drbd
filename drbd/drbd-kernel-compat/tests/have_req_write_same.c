/* {"version": "3.7", "commit": "4363ac7c13a9a4b763c6e8d9fdbfc2468f3b8ca4", "comment": "WRITE_SAME is not supported before 3.7", "author": "Martin K. Petersen <martin.petersen@oracle.com>", "date": "Tue Sep 18 12:19:27 2012 -0400"} */
#include <linux/blk_types.h>

/* NOTE: this was removed again and subsequently renamed in
 * v4.7-rc2-42-g4e1b2d52a80d, see have_req_op_write_same.c */
enum rq_flag_bits dummy = REQ_WRITE_SAME;
