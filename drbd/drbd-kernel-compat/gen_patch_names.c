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

	patch(1, "timer_setup", true, false,
	      COMPAT_HAVE_TIMER_SETUP, "present");

#if defined(COMPAT_HAVE_BLK_QUEUE_SPLIT_BIO)
	/* "modern" version (>=5.9) with only 1 argument. nothing to do */
#elif defined(COMPAT_HAVE_BLK_QUEUE_SPLIT_Q_BIO)
	/* older version with 2 arguments */
	patch(1, "blk_queue_split", false, true,
	      YES, "has_two_parameters");
#elif defined(COMPAT_HAVE_BLK_QUEUE_SPLIT_Q_BIO_BIOSET)
	/* even older version with 3 arguments */
	patch(1, "blk_queue_split", false, true,
	      YES, "has_three_parameters");
	patch(1, "make_request", false, true,
	      COMPAT_NEED_MAKE_REQUEST_RECURSION, "need_recursion");
#else
	/* ancient version, blk_queue_split not defined at all */
	patch(1, "blk_queue_split", true, false,
	      NO, "present");
#endif

	patch(1, "bio_alloc", true, false,
	      COMPAT_BIO_ALLOC_HAS_4_PARAMS, "has_4_params");

	patch(1, "bio_alloc_clone", true, false,
	      COMPAT_HAVE_BIO_ALLOC_CLONE, "present");

#if !defined(COMPAT_HAVE_BIO_SET_DEV)
	patch(1, "bio_set_dev", true, false,
	      COMPAT_HAVE_BIO_SET_DEV, "present");
#endif

	patch(1, "bio_bi_bdev", true, false,
	      COMPAT_HAVE_BIO_BI_BDEV, "present");

	patch(1, "refcount_inc", true, false,
	      COMPAT_HAVE_REFCOUNT_INC, "present");

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

	patch(1, "blk_alloc_disk", true, false,
	      COMPAT_HAVE_BLK_ALLOC_DISK, "present");

/*******************************************************************************/
	/*
	 * if COMPAT_HAVE_VOID_SUBMIT_BIO is unset, that can mean one of two
	 * things:
	 * - the kernel uses submit_bio, but with a blk_qc_t return value
	 * - the kernel does not use submit_bio at all (but uses make_request)
	 *
	 * regardless of which of these is true, we need to patch our submit_bio
	 * back to the blk_qc_t based version. this makes sure the further
	 * "back-patches" (like submit_bio -> make_request) actually match.
	 */
	patch(1, "submit_bio", true, false,
	      COMPAT_HAVE_VOID_SUBMIT_BIO, "returns_void");

#if defined(COMPAT_HAVE_BLK_QC_T_SUBMIT_BIO) || defined(COMPAT_HAVE_VOID_SUBMIT_BIO)
	/*
	 * modern version (>=v5.9), make_request_fn moved to
	 * submit_bio block_device_operation.
	 * nothing to do.
	 */
#else
	/* old versions (<v5.9), using make_request_fn */
	patch(1, "submit_bio", true, false,
	      NO, "present");

	patch(1, "blk_alloc_queue_rh", false, true,
		COMPAT_HAVE_BLK_ALLOC_QUEUE_RH, "present");

	patch(1, "blk_queue_make_request", false, true,
	      COMPAT_HAVE_BLK_QUEUE_MAKE_REQUEST, "present");

	patch(1, "req_hardbarrier", false, true,
	      COMPAT_HAVE_REQ_HARDBARRIER, "present");
# if defined(COMPAT_HAVE_BLK_QC_T_MAKE_REQUEST)
	/* older version (v4.3-v5.9): make_request function pointer
	 * with blk_qc_t return value. most modern make_request based version,
	 * so nothing more to do. */
# elif defined(COMPAT_HAVE_VOID_MAKE_REQUEST)
	/* even older version (v3.1-v4.3): void return value */
	patch(1, "make_request", false, true,
	      YES, "returns_void");
# else
	/* ancient version (<v3.1): int return value */
	patch(1, "make_request", false, true,
	      YES, "returns_int");
# endif
#endif
/*******************************************************************************/

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

	patch(1, "idr_is_empty", true, false,
	      COMPAT_HAVE_IDR_IS_EMPTY, "present");

	patch(1, "sock_create_kern", true, false,
	      COMPAT_SOCK_CREATE_KERN_HAS_FIVE_PARAMETERS, "has_five_parameters");

	patch(1, "time64_to_tm", true, false,
	      COMPAT_HAVE_TIME64_TO_TM, "present");

	patch(1, "ktime_to_timespec64", true, false,
	      COMPAT_HAVE_KTIME_TO_TIMESPEC64, "present");

	patch(1, "d_inode", true, false,
	      COMPAT_HAVE_D_INODE, "present");

	patch(1, "inode_lock", true, false,
	      COMPAT_HAVE_INODE_LOCK, "present");

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

	patch(1, "genl_policy", true, false,
	      COMPAT_GENL_POLICY_IN_OPS, "in_ops");

	patch(1, "blk_queue_merge_bvec", false, true,
	      COMPAT_HAVE_BLK_QUEUE_MERGE_BVEC, "present");

	patch(1, "security_netlink_recv", false, true,
	      COMPAT_HAVE_SECURITY_NETLINK_RECV, "present");

#if defined(COMPAT_HAVE_QUEUE_FLAG_STABLE_WRITES)
	/* in versions >=5.9, there is QUEUE_FLAG_STABLE_WRITES */
#else
	/* for <5.9 but >=3.9, fall back to BDI_CAP_STABLE_WRITES */
	patch(1, "queue_flag_stable_writes", true, false,
	      NO, "present");
#endif

	patch(1, "queue_flag_discard", false, true,
	      COMPAT_HAVE_QUEUE_FLAG_DISCARD, "present");

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

#if defined(COMPAT_HAVE_REQ_WRITE)
	/* This is the oldest version, using REQ_* flags. The bio ops
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

	patch(1, "security_netlink_recv", false, true,
	      COMPAT_HAVE_SECURITY_NETLINK_RECV, "present");

	patch(1, "nla_nest_start_noflag", true, false,
	      COMPAT_HAVE_NLA_NEST_START_NOFLAG, "present");

	patch(1, "nla_parse_deprecated", true, false,
	      COMPAT_HAVE_NLA_PARSE_DEPRECATED, "present");

	patch(1, "allow_kernel_signal", true, false,
	      COMPAT_HAVE_ALLOW_KERNEL_SIGNAL, "present");

	patch(1, "rb_declare_callbacks_max", true, false,
	      COMPAT_HAVE_RB_DECLARE_CALLBACKS_MAX, "present");

	patch(1, "struct_size", true, false,
	      COMPAT_HAVE_STRUCT_SIZE, "present");

	patch(1, "part_stat_h", true, false,
	      COMPAT_HAVE_PART_STAT_H, "present");

	patch(1, "__vmalloc", true, false,
	      COMPAT___VMALLOC_HAS_2_PARAMS, "has_2_params");

	patch(1, "tcp_sock_set_cork", true, false,
	      COMPAT_HAVE_TCP_SOCK_SET_CORK, "present");

	patch(1, "tcp_sock_set_nodelay", true, false,
	      COMPAT_HAVE_TCP_SOCK_SET_NODELAY, "present");

	patch(1, "tcp_sock_set_quickack", true, false,
	      COMPAT_HAVE_TCP_SOCK_SET_QUICKACK, "present");

	patch(1, "sock_set_keepalive", true, false,
	      COMPAT_HAVE_SOCK_SET_KEEPALIVE, "present");

	patch(1, "submit_bio_noacct", true, false,
	      COMPAT_HAVE_SUBMIT_BIO_NOACCT, "present");

	patch(1, "bdi_congested", false, true,
	      COMPAT_HAVE_BDI_CONGESTED, "present");

	patch(1, "congested_fn", false, true,
	      COMPAT_HAVE_BDI_CONGESTED_FN, "present");

	patch(1, "wb_congested_enum", true, false,
	      COMPAT_HAVE_WB_CONGESTED_ENUM, "present");

	patch(1, "disk_update_readahead", true, false,
	      COMPAT_HAVE_DISK_UPDATE_READAHEAD, "present");

#if !defined(COMPAT_HAVE_DISK_UPDATE_READAHEAD)
	/* disk_update_readahead is the "new version" of
	 * blk_queue_update_readahead. we only need to consider compat
	 * for the old function if we don't already have the new one. */
	patch(1, "blk_queue_update_readahead", true, false,
	      COMPAT_HAVE_BLK_QUEUE_UPDATE_READAHEAD, "present");
#endif

	patch(1, "struct_gendisk", true, false,
	      COMPAT_STRUCT_GENDISK_HAS_BACKING_DEV_INFO, "has_backing_dev_info");

#if !defined(COMPAT_STRUCT_GENDISK_HAS_BACKING_DEV_INFO)
	patch(1, "backing_dev_info", true, false,
	      COMPAT_HAVE_POINTER_BACKING_DEV_INFO, "is_pointer");
#endif

	patch(1, "sendpage_ok", true, false,
	      COMPAT_HAVE_SENDPAGE_OK, "present");

	patch(1, "fallthrough", true, false,
	      COMPAT_HAVE_FALLTHROUGH, "present");

	patch(1, "set_capacity_and_notify", true, false,
	      COMPAT_HAVE_SET_CAPACITY_AND_NOTIFY, "present");

/* revalidate_disk_size was removed 2 months after it was added.
 * So we need to differentiate whether revalidate_disk_size has never existed yet,
 * or if it has existed and it is now gone again. If it is already gone again,
 * we don't need it anyways because we now have set_capacity_and_notify in its
 * place.
 * -> If we have set_capacity_and_notify, it already got removed.
 * -> If we don't have set_capacity_and_notify, it was not yet added. */
#if !defined(COMPAT_HAVE_REVALIDATE_DISK_SIZE) && !defined(COMPAT_HAVE_SET_CAPACITY_AND_NOTIFY)
	patch(1, "revalidate_disk_size", true, false,
	      NO, "present");
#endif

	patch(1, "sched_set_fifo", true, false,
	      COMPAT_HAVE_SCHED_SET_FIFO, "present");

	patch(1, "vermagic_h", false, true,
	      COMPAT_CAN_INCLUDE_VERMAGIC_H, "can_include");

	patch(1, "nla_strscpy", true, false,
	      COMPAT_HAVE_NLA_STRSCPY, "present");

	patch(1, "queue_discard_zeroes_data", true, false,
	      COMPAT_QUEUE_LIMITS_HAS_DISCARD_ZEROES_DATA, "present");

#if !defined(COMPAT_HAVE_BLK_QUEUE_WRITE_CACHE)
	patch(2, "blk_queue_write_cache", true, false,
	      COMPAT_HAVE_BLK_QUEUE_WRITE_CACHE, "present",
# if defined(COMPAT_HAVE_REQ_HARDBARRIER)
	      NO, "flush"
# else
	      YES, "flush"
# endif
	);
#endif

	patch(1, "crypto_tfm_need_key", true, false,
	      COMPAT_HAVE_CRYPTO_TFM_NEED_KEY, "present");

	patch(1, "part_stat_read", true, false,
	      COMPAT_PART_STAT_READ_TAKES_BLOCK_DEVICE, "takes_block_device");

	patch(1, "part_stat_read_accum", true, false,
	      COMPAT_HAVE_PART_STAT_READ_ACCUM, "present");

	patch(1, "bdgrab", false, true,
	      COMPAT_HAVE_BDGRAB, "present");

/* hd_struct is the old struct; got merged into block_device.
 * so if we still have hd_struct, part0 will not be a block_device. */
#if defined(COMPAT_HAVE_HD_STRUCT)
	patch(1, "gendisk_part0", true, false,
	      NO, "is_block_device");
#endif

	patch(1, "bio_max_vecs", true, false,
	      COMPAT_HAVE_BIO_MAX_VECS, "present");

	patch(1, "fs_dax_get_by_bdev", true, false,
	      COMPAT_HAVE_FS_DAX_GET_BY_BDEV, "present");

#if defined(COMPAT_HAVE_FS_DAX_GET_BY_BDEV)
	patch(1, "fs_dax_get_by_bdev", true, false,
	      COMPAT_FS_DAX_GET_BY_BDEV_TAKES_START_OFF, "takes_start_off");
#endif

	patch(1, "add_disk", true, false,
	      COMPAT_ADD_DISK_RETURNS_INT, "returns_int");

	patch(1, "bdev_nr_sectors", true, false,
	      COMPAT_HAVE_BDEV_NR_SECTORS, "present");

	patch(1, "genhd_fl_no_part", true, false,
	      COMPAT_HAVE_GENHD_FL_NO_PART, "present");

	patch(1, "dax_direct_access", true, false,
	      COMPAT_DAX_DIRECT_ACCESS_TAKES_MODE, "takes_mode");

	patch(1, "bdev_max_discard_sectors", true, false,
	      COMPAT_HAVE_BDEV_MAX_DISCARD_SECTORS, "present");

	patch(1, "blk_queue_max_write_same_sectors", false, true,
	      COMPAT_HAVE_BLK_QUEUE_MAX_WRITE_SAME_SECTORS, "present");

	patch(1, "blkdev_issue_discard", false, true,
	      COMPAT_BLKDEV_ISSUE_DISCARD_TAKES_FLAGS, "takes_flags");

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
