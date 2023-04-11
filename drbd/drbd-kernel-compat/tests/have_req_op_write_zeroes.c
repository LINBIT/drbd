/* { "version": "v4.10-rc1", "commit": "a6f0788ec2881ac14e97ff7fa6a78a807f87b5ba", "comment": "add support for REQ_OP_WRITE_ZEROES", "author": "Chaitanya Kulkarni <chaitanya.kulkarni@hgst.com>", "date": "Wed Nov 30 12:28:59 2016 -0800" } */

#include <linux/blk_types.h>

int dummy = REQ_OP_WRITE_ZEROES;
