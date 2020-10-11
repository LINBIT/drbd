#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <linux/limits.h>
#include "compat.h"

#define SEP "_"

#define ARRAY_LEN(a) (sizeof(a)/sizeof((a))[0])

#define __append(s) do {						\
	if (ARRAY_LEN(buf) - strlen(buf) < strlen(s) + 1) {		\
		fprintf(stderr, "BUFSIZE too small, aborting\n");	\
		exit(1);						\
	}								\
	strcat(buf, s);							\
} while(0)

/* this is the tricky part:
 * if a define is defined but empty (e.g., #define X), it is stringified: ""
 * if a define is not defined, we get the stringified name of the macro: "X"
 * This would produce false output if something is actually defined to a value (e.g., #define X foo)
 * our compat.h fulfils these properties, but use that machinery with care!
 * This is as good as it gets with cpp, m4 FTW ;-) */
#define _append(d,n) do {		\
	if (strlen(#d) == 0) {		\
		__append("yes" SEP);	\
		all_no = false;		\
	} else {			\
		__append("no" SEP);	\
		all_yes = false;	\
	}				\
	__append(n);			\
} while(0)

#define append1(d1,n1)			do {_append(d1,n1);} while(0)
#define append2(d1,n1,d2,n2)		do {_append(d1,n1); __append(SEP SEP); _append(d2,n2);} while(0)
#define append3(d1,n1,d2,n2,d3,n3)	do {_append(d1,n1); __append(SEP SEP); _append(d2,n2); __append(SEP SEP); _append(d3,n3);} while(0)

/* iay == IgnoreAllYes, do not generate output if all defines are defined
 * ian == IgnoreAllNo, do not generate output if none of the defines is defined */
#define patch(n,name,iay,ian,...) do {			\
	bool all_yes = true, all_no = true;             \
	buf[0] = '\0';                                  \
	__append(name SEP SEP);				\
	append##n(__VA_ARGS__);				\
	if (! ((iay && all_yes) || (ian && all_no)) ) {	\
		for (int i = 0; i < strlen(buf); i++)   \
			buf[i] = tolower(buf[i]);       \
		printf("%s\n", buf);                    \
	}						\
} while(0)

/* This can be used to always unconditionally apply a patch. */
#define YES
/* #undef NO */

int main(int argc, char **argv)
{
	/* shared buffer */
	char buf[PATH_MAX] = {0};

	/* ONLY TRUE */
	/* patch(1, "footrue", false, true, FOO, "foo"); */

	/* ONLY FALSE */
	/* patch(1, "foofalse", true, false, FOO, "foo"); */

	/* BOTH CASES */
	/* patch(1, "fooboth", false, false, FOO, "foo"); */

	/* we have nothing, need all of them */
	/* patch(2, "none", false, false, */
	/* 		COMPAT_BLKDEV_ISSUE_ZEROOUT_DISCARD, "discard", */
	/* 		COMPAT_BLKDEV_ISSUE_ZEROOUT_BLKDEV_IFL_WAIT, "ifl_wait"); */
	/* #<{(| we have all of this, need none them |)}># */
	/* patch(2, "2nd_feature", false, false, */
	/* 		COMPAT_HAVE_ATOMIC_IN_FLIGHT, "atomic_in_flight", */
	/* 		COMPAT_HAVE_BD_CLAIM_BY_DISK, "bd_claim_by_disk"); */

	patch(1, "block_device_operations_release", true, false,
	      COMPAT_DRBD_RELEASE_RETURNS_VOID, "is_void");

#if !defined(COMPAT_HAVE_BD_UNLINK_DISK_HOLDER) || defined(COMPAT_HAVE_BD_CLAIM_BY)
	patch(2, "claim_disk", true, false,
	      COMPAT_HAVE_BD_UNLINK_DISK_HOLDER, "link",
	      COMPAT_HAVE_BD_CLAIM_BY_DISK, "claim");
#endif

	patch(1, "timer_setup", true, false,
	      COMPAT_HAVE_TIMER_SETUP, "present");

	patch(1, "bio_bi_bdev", false, true,
	      COMPAT_HAVE_BIO_BI_BDEV, "present");

	patch(1, "refcount_inc", true, false,
	      COMPAT_HAVE_REFCOUNT_INC, "present");

	patch(1, "netlink_cb_portid", true, false,
	      COMPAT_HAVE_NETLINK_CB_PORTID, "present");

	patch(1, "prandom_u32", true, false,
	      COMPAT_HAVE_PRANDOM_U32, "present");

	patch(1, "struct_bvec_iter", true, false,
	      COMPAT_HAVE_STRUCT_BVEC_ITER, "present");

	patch(1, "rdma_create_id", true, false,
	      COMPAT_RDMA_CREATE_ID_HAS_NET_NS, "has_net_ns");

	patch(1, "ib_device", true, false,
	      COMPAT_IB_DEVICE_HAS_OPS, "has_ops");

#ifndef COMPAT_IB_DEVICE_HAS_OPS
	patch(1, "ib_query_device", true, false,
	      COMPAT_IB_QUERY_DEVICE_HAS_3_PARAMS, "has_3_params");
#endif

	patch(1, "ib_alloc_pd", true, false,
	      COMPAT_IB_ALLOC_PD_HAS_2_PARAMS, "has_2_params");

	patch(1, "ib_post", true, false,
	      COMPAT_IB_POST_SEND_CONST_PARAMS, "const");

	patch(1, "req_hardbarrier", false, true,
	      COMPAT_HAVE_REQ_HARDBARRIER, "present");

	patch(1, "blk_queue_make_request", false, true,
	      COMPAT_HAVE_BLK_QUEUE_MAKE_REQUEST, "present");

#ifndef COMPAT_HAVE_BLK_QC_T_MAKE_REQUEST
	patch(2, "make_request", false, false,
	      COMPAT_HAVE_BLK_QC_T_MAKE_REQUEST, "is_blk_qc_t",
	      COMPAT_HAVE_VOID_MAKE_REQUEST, "is_void");
#endif

	patch(1, "blkdev_get_by_path", true, false,
	      COMPAT_HAVE_BLKDEV_GET_BY_PATH, "present");

#if !defined(COMPAT_HAVE_BIO_BI_STATUS)
	patch(2, "bio", false, false,
	      COMPAT_HAVE_BIO_BI_STATUS, "bi_status",
	      COMPAT_HAVE_BIO_BI_ERROR, "bi_error");

	patch(1, "bio", false, false,
	      COMPAT_HAVE_BIO_BI_STATUS, "bi_status");
#endif

	patch(1, "kernel_read", false, true,
	      COMPAT_BEFORE_4_13_KERNEL_READ, "before_4_13");

	patch(1, "sock_ops", true, false,
	      COMPAT_SOCK_OPS_RETURNS_ADDR_LEN, "returns_addr_len");

	patch(1, "hlist_for_each_entry", true, false,
	      COMPAT_HLIST_FOR_EACH_ENTRY_HAS_THREE_PARAMETERS, "has_three_parameters");

	patch(1, "idr_is_empty", true, false,
	      COMPAT_HAVE_IDR_IS_EMPTY, "present");

	patch(1, "sock_create_kern", true, false,
	      COMPAT_SOCK_CREATE_KERN_HAS_FIVE_PARAMETERS, "has_five_parameters");

	patch(1, "wb_congested_enum", true, false,
	      COMPAT_HAVE_WB_CONGESTED_ENUM, "present");

	patch(1, "time64_to_tm", true, false,
	      COMPAT_HAVE_TIME64_TO_TM, "present");

	patch(1, "ktime_to_timespec64", true, false,
	      COMPAT_HAVE_KTIME_TO_TIMESPEC64, "present");

	patch(1, "file_inode", true, false,
	      COMPAT_HAVE_FILE_INODE, "present");

	patch(1, "d_inode", true, false,
	      COMPAT_HAVE_D_INODE, "present");

	patch(1, "inode_lock", true, false,
	      COMPAT_HAVE_INODE_LOCK, "present");

	patch(1, "ratelimit_state_init", true, false,
	      COMPAT_HAVE_RATELIMIT_STATE_INIT, "present");

#ifndef COMPAT_HAVE_BIOSET_INIT
	patch(1, "bioset_init", true, false,
	      COMPAT_HAVE_BIOSET_INIT, "present");

	patch(2, "bioset_init", true, false,
	      COMPAT_HAVE_BIOSET_INIT, "present",
	      COMPAT_HAVE_BIO_CLONE_FAST, "bio_clone_fast");

	patch(2, "bioset_init", true, false,
	      COMPAT_HAVE_BIOSET_INIT, "present",
	      COMPAT_HAVE_BIOSET_NEED_BVECS, "need_bvecs");
#endif

	patch(1, "kvfree", true, false,
	      COMPAT_HAVE_KVFREE, "present");

	patch(1, "bio_free", false, true,
	      COMPAT_HAVE_BIO_FREE, "present");

	patch(1, "genl_policy", false, true,
	      COMPAT_GENL_POLICY_IN_OPS, "in_ops");

	patch(1, "blk_queue_merge_bvec", false, true,
	      COMPAT_HAVE_BLK_QUEUE_MERGE_BVEC, "present");

#if !defined(COMPAT_HAVE_BLK_QUEUE_SPLIT_Q_BIO)
# if defined(COMPAT_HAVE_BLK_QUEUE_SPLIT_Q_BIO_BIOSET)
	/* if _BIOSET is true, it's the variant with 3 arguments */
	patch(1, "blk_queue_split", false, true,
	      YES, "bioset");
	patch(1, "make_request", false, true,
	      COMPAT_NEED_MAKE_REQUEST_RECURSION, "need_recursion");
# else
	/* if _BIOSET is also false, it's not present at all */
	patch(1, "blk_queue_split", true, false,
	      NO, "present");
# endif
#endif

	patch(1, "security_netlink_recv", false, true,
	      COMPAT_HAVE_SECURITY_NETLINK_RECV, "present");

	patch(1, "blk_queue_flag_set", true, false,
	      COMPAT_HAVE_BLK_QUEUE_FLAG_SET, "present");

	patch(1, "req_noidle", false, true,
	      COMPAT_HAVE_REQ_NOIDLE, "present");

	patch(1, "req_nounmap", true, false,
	      COMPAT_HAVE_REQ_NOUNMAP, "present");

	patch(1, "bio_op_shift", false, true,
	      COMPAT_HAVE_BIO_OP_SHIFT, "present");

	patch(1, "write_zeroes", true, false,
	      COMPAT_HAVE_REQ_OP_WRITE_ZEROES, "capable");

#if !defined(COMPAT_HAVE_REQ_OP_WRITE_SAME) && \
	!defined(COMPAT_HAVE_REQ_WRITE_SAME)
	patch(1, "write_same", true, false,
	      NO, "capable");
#endif

	patch(1, "bio_bi_opf", true, false,
	      COMPAT_HAVE_BIO_BI_OPF, "present");

#if defined(COMPAT_HAVE_BIO_START_IO_ACCT)
	/* good, newest version */
#else
	patch(1, "bio_start_io_acct", true, false,
	      NO, "present");
# if defined(COMPAT_HAVE_GENERIC_START_IO_ACCT_Q_RW_SECT_PART)
	/* older version, 4 params */
# elif defined(COMPAT_HAVE_GENERIC_START_IO_ACCT_RW_SECT_PART)
	/* even, older version, 3 params */
	patch(1, "generic_start_io_acct", true, false,
	      NO, "has_four_params");
# else
	/* not present at all */
	patch(1, "generic_start_io_acct", true, false,
	      NO, "present");
# endif
#endif

#if defined(COMPAT_HAVE_BIO_RW)
	/* This is the oldest supported version, using BIO_*. Read/write
	 * direction is controlled by a single bit (BIO_RW). */
	patch(1, "bio_rw", false, true,
	      YES, "present");
#elif defined(COMPAT_HAVE_REQ_WRITE)
	/* This is an intermediate version, using REQ_* flags. The bio ops
	 * and flags are separated, and it's using bio->bi_rw and bi_flags,
	 * respectively */
	patch(1, "req_write", false, true,
	      YES, "present");
#elif defined(COMPAT_HAVE_REQ_OP_WRITE)
	/* We're dealing with a "modern" kernel which has REQ_OP_* flags.
	 * It has separate bio operations (bio->bi_opf) and flags
	 * (bio->bi_flags). */
#else
# warning "Unknown bio rw flags, check compat layer"
#endif

	patch(1, "blk_check_plugged", true, false,
	      COMPAT_HAVE_BLK_CHECK_PLUGGED, "present");

	patch(1, "kmap_atomic", true, false,
	      COMPAT_KMAP_ATOMIC_PAGE_ONLY, "page_only");

	patch(1, "blk_queue_plugged", false, true,
	      COMPAT_HAVE_BLK_QUEUE_PLUGGED, "present");

	patch(1, "alloc_workqueue", true, false,
	      COMPAT_ALLOC_WORKQUEUE_TAKES_FMT, "takes_fmt");

	patch(1, "struct_kernel_param_ops", true, false,
	      COMPAT_HAVE_STRUCT_KERNEL_PARAM_OPS, "present");

	patch(1, "req_prio", true, false,
	      COMPAT_HAVE_REQ_PRIO, "present");

	patch(1, "bio_flush", false, true,
	      COMPAT_HAVE_BIO_FLUSH, "present");

	patch(1, "nla_nest_start_noflag", true, false,
	      COMPAT_HAVE_NLA_NEST_START_NOFLAG, "present");

	patch(1, "nla_parse_deprecated", true, false,
	      COMPAT_HAVE_NLA_PARSE_DEPRECATED, "present");

	patch(1, "allow_kernel_signal", true, false,
	      COMPAT_HAVE_ALLOW_KERNEL_SIGNAL, "present");

	patch(1, "struct_size", true, false,
	      COMPAT_HAVE_STRUCT_SIZE, "present");

	patch(1, "part_stat_h", true, false,
	      COMPAT_HAVE_PART_STAT_H, "present");

	patch(1, "__vmalloc", true, false,
	      COMPAT___VMALLOC_HAS_2_PARAMS, "has_2_params");

/* #define BLKDEV_ISSUE_ZEROOUT_EXPORTED */
/* #define BLKDEV_ZERO_NOUNMAP */

// #ifndef BLKDEV_ISSUE_ZEROOUT_EXPORTED
/* Was introduced with 2.6.34 */
//	patch(1, "zeroout", false, false,
//			BLKDEV_ISSUE_ZEROOUT_EXPORTED, "exported");
//#else
/* synopsis changed a few times, though */
//#if  defined(BLKDEV_ZERO_NOUNMAP)
/* >= v4.12 */
/* use blkdev_issue_zeroout() as written out in the actual source code.
 * right now, we only use it with flags = BLKDEV_ZERO_NOUNMAP */

/* no op */
//#else
//	patch(2, "zeroout", false, false,
//			COMPAT_BLKDEV_ISSUE_ZEROOUT_BLKDEV_IFL_WAIT, "ifl_wait",
//		  			COMPAT_BLKDEV_ISSUE_ZEROOUT_DISCARD, "discard");
//#endif
//#endif

	return 0;
}
