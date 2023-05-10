/* { "version": "v4.7-rc3", "commit": "f21508211d2b16e65821abd171378fa6ece126fe", "comment": "enum req_op was added", "author": "Mike Christie <mchristi@redhat.com>", "date": "Sun Jun 5 14:31:42 2016 -0500" } */

/*
 * NOTE: this tests for the same commit as have_req_op_write.c, but it still needs a separate test.
 *
 * 2016-06-05 f2150821: "enum req_op" was introduced
 * 2016-10-28 ef295ecf: renamed to "enum req_opf"
 * 2022-07-14 ff07a02e: renamed back to "enum req_op"
 * 
 * So: some old kernels have "enum req_op", most have "enum req_opf", and the (current) newest have
 * "enum req_op" again; while all of them have the REQ_OP_* flags.
 */

#include <linux/blk_types.h>

enum req_op dummy = REQ_OP_WRITE;
