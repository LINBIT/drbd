#ifndef _DRBD_WRAPPERS_H
#define _DRBD_WRAPPERS_H

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
# error "At least kernel 2.6.32 (with patches) required"
#endif

#include "compat.h"
#include <linux/ctype.h>
#include <linux/net.h>
#include <linux/version.h>
#include <linux/crypto.h>
#include <linux/netlink.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/proc_fs.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/kernel.h>
#include <linux/kconfig.h>

#ifndef pr_fmt
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt
#endif

#ifndef U32_MAX
#define U32_MAX ((u32)~0U)
#endif
#ifndef S32_MAX
#define S32_MAX ((s32)(U32_MAX>>1))
#endif

#ifndef READ_ONCE
#define READ_ONCE ACCESS_ONCE
#endif

#ifndef __GFP_RECLAIM
#define __GFP_RECLAIM __GFP_WAIT
#endif

#ifndef FMODE_EXCL
#define FMODE_EXCL 0
#endif

#ifndef lockdep_assert_irqs_disabled
#define lockdep_assert_irqs_disabled() do { } while (0)
#endif

#if defined(CONFIG_DYNAMIC_DEBUG)
#if !defined(dynamic_pr_debug) || !defined(DEFINE_DYNAMIC_DEBUG_METADATA)
#warning "CONFIG_DYNAMIC_DEBUG is defined, but some related macro is not; disabling dynamic debug"
#define DEFINE_DYNAMIC_DEBUG_METADATA(D, F) const char *D = F
#define __dynamic_pr_debug(D, F, args...) do { (void)(D); if (0) printk(F, ## args); } while(0)
#define DYNAMIC_DEBUG_BRANCH(D) false
#endif

#ifndef DYNAMIC_DEBUG_BRANCH
#define DYNAMIC_DEBUG_BRANCH(descriptor) \
	(unlikely(descriptor.flags & _DPRINTK_FLAGS_PRINT))
#endif
#endif

#ifndef KREF_INIT
#define KREF_INIT(N) { ATOMIC_INIT(N) }
#endif

/* history of bioset_create():
 *  v4.13  011067b  blk: replace bioset_create_nobvec() with a flags arg to bioset_create()
 *  +struct bio_set *bioset_create(unsigned int pool_size, unsigned int front_pad, int flags)
 *
 *  v3.18  d8f429e  block: add bioset_create_nobvec()
 *  +struct bio_set *bioset_create(unsigned int pool_size, unsigned int front_pad)
 *  +struct bio_set *bioset_create_nobvec(unsigned int pool_size, unsigned int front_pad)
 *
 *  v3.16  f9c78b2  block: move bio.c and bio-integrity.c from fs/ to block/
 *  +struct bio_set *bioset_create(unsigned int pool_size, unsigned int front_pad)
 *
 *  --- we don't care for older than 2.3.32 ---
 */
#if defined(COMPAT_HAVE_BIOSET_NEED_BVECS)
/* all good, "modern" kernel before v4.18 */
#elif defined(COMPAT_HAVE_BIOSET_CREATE_FRONT_PAD)
# define bioset_create(pool_size, front_pad, flags) bioset_create(pool_size, front_pad)
#elif defined(COMPAT_HAVE_BIOSET_INIT)
/* => v4.18*/
#else
# error "drbd compat layer broken"
#endif


#if !(defined(COMPAT_HAVE_RB_AUGMENT_FUNCTIONS) && \
      defined(AUGMENTED_RBTREE_SYMBOLS_EXPORTED))

/*
 * Make sure the replacements for the augmented rbtree helper functions do not
 * clash with functions the kernel implements but does not export.
 */
#define rb_augment_f drbd_rb_augment_f
#define rb_augment_path drbd_rb_augment_path
#define rb_augment_insert drbd_rb_augment_insert
#define rb_augment_erase_begin drbd_rb_augment_erase_begin
#define rb_augment_erase_end drbd_rb_augment_erase_end

typedef void (*rb_augment_f)(struct rb_node *node, void *data);

static inline void rb_augment_path(struct rb_node *node, rb_augment_f func, void *data)
{
	struct rb_node *parent;

up:
	func(node, data);
	parent = rb_parent(node);
	if (!parent)
		return;

	if (node == parent->rb_left && parent->rb_right)
		func(parent->rb_right, data);
	else if (parent->rb_left)
		func(parent->rb_left, data);

	node = parent;
	goto up;
}

/*
 * after inserting @node into the tree, update the tree to account for
 * both the new entry and any damage done by rebalance
 */
static inline void rb_augment_insert(struct rb_node *node, rb_augment_f func, void *data)
{
	if (node->rb_left)
		node = node->rb_left;
	else if (node->rb_right)
		node = node->rb_right;

	rb_augment_path(node, func, data);
}

/*
 * before removing the node, find the deepest node on the rebalance path
 * that will still be there after @node gets removed
 */
static inline struct rb_node *rb_augment_erase_begin(struct rb_node *node)
{
	struct rb_node *deepest;

	if (!node->rb_right && !node->rb_left)
		deepest = rb_parent(node);
	else if (!node->rb_right)
		deepest = node->rb_left;
	else if (!node->rb_left)
		deepest = node->rb_right;
	else {
		deepest = rb_next(node);
		if (deepest->rb_right)
			deepest = deepest->rb_right;
		else if (rb_parent(deepest) != node)
			deepest = rb_parent(deepest);
	}

	return deepest;
}

/*
 * after removal, update the tree to account for the removed entry
 * and any rebalance damage.
 */
static inline void rb_augment_erase_end(struct rb_node *node, rb_augment_f func, void *data)
{
	if (node)
		rb_augment_path(node, func, data);
}
#endif

#ifndef IDR_GET_NEXT_EXPORTED
/* Body in compat/idr.c */
extern void *idr_get_next(struct idr *idp, int *nextidp);
#endif

/**
 * idr_for_each_entry - iterate over an idr's elements of a given type
 * @idp:     idr handle
 * @entry:   the type * to use as cursor
 * @id:      id entry's key
 */
/* introduced in v3.1-rc1-39-g9749f30f1a38 */
#ifndef idr_for_each_entry
#define idr_for_each_entry(idp, entry, id)				\
	for (id = 0, entry = (typeof(entry))idr_get_next((idp), &(id)); \
	     entry != NULL;						\
	     ++id, entry = (typeof(entry))idr_get_next((idp), &(id)))
#endif

/* introduced in v4.4-rc2-61-ga55bbd375d18 */
#ifndef idr_for_each_entry_continue
#define idr_for_each_entry_continue(idp, entry, id)			\
	for (entry = (typeof(entry))idr_get_next((idp), &(id));		\
	     entry;							\
	     ++id, entry = (typeof(entry))idr_get_next((idp), &(id)))
#endif


#ifndef RCU_INITIALIZER
#define RCU_INITIALIZER(v) (typeof(*(v)) *)(v)
#endif

#ifndef list_next_entry
/* introduced in 008208c (v3.13-rc1) */
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)
#endif

/*
 * v4.12 fceb6435e852 netlink: pass extended ACK struct to parsing functions
 * and some preparation commits introduce a new "netlink extended ack" error
 * reporting mechanism. For now, only work around that here.  As trigger, use
 * NETLINK_MAX_COOKIE_LEN introduced somewhere in the middle of that patchset.
 */
#ifndef NETLINK_MAX_COOKIE_LEN
#include <net/netlink.h>
#define nla_parse_nested(tb, maxtype, nla, policy, extack) \
       nla_parse_nested(tb, maxtype, nla, policy)
#endif

#ifndef SK_CAN_REUSE
/* This constant was introduced by Pavel Emelyanov <xemul@parallels.com> on
   Thu Apr 19 03:39:36 2012 +0000. Before the release of linux-3.5
   commit 4a17fd52 sock: Introduce named constants for sk_reuse */
#define SK_CAN_REUSE   1
#endif

#ifndef COMPAT_HAVE_IDR_ALLOC
static inline int idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp_mask)
{
	int rv, got;

	if (!idr_pre_get(idr, gfp_mask))
		return -ENOMEM;
	rv = idr_get_new_above(idr, ptr, start, &got);
	if (rv < 0)
		return rv;

	if (got >= end) {
		idr_remove(idr, got);
		return -ENOSPC;
	}

	return got;
}
#endif

#ifndef BLKDEV_ISSUE_ZEROOUT_EXPORTED
/* Was introduced with 2.6.34 */
extern int blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
				sector_t nr_sects, gfp_t gfp_mask);
#define blkdev_issue_zeroout(BDEV, SS, NS, GFP, flags /* = NOUNMAP */) \
	blkdev_issue_zeroout(BDEV, SS, NS, GFP)
#else
/* synopsis changed a few times, though */
#if  defined(BLKDEV_ZERO_NOUNMAP)
/* >= v4.12 */
/* use blkdev_issue_zeroout() as written out in the actual source code.
 * right now, we only use it with flags = BLKDEV_ZERO_NOUNMAP */
#elif  defined(COMPAT_BLKDEV_ISSUE_ZEROOUT_DISCARD)
/* no BLKDEV_ZERO_NOUNMAP as last parameter, but a bool discard instead */
/* still need to define BLKDEV_ZERO_NOUNMAP, to compare against 0 */
#define BLKDEV_ZERO_NOUNMAP 1
#define blkdev_issue_zeroout(BDEV, SS, NS, GFP, flags /* = NOUNMAP */) \
	blkdev_issue_zeroout(BDEV, SS, NS, GFP, (flags) == 0 /* bool discard */)
#else /* !defined(COMPAT_BLKDEV_ISSUE_ZEROOUT_DISCARD) */
#define blkdev_issue_zeroout(BDEV, SS, NS, GFP, discard) \
	blkdev_issue_zeroout(BDEV, SS, NS, GFP)
#endif
#endif


#if !defined(QUEUE_FLAG_SECDISCARD)
# define queue_flag_set_unlocked(F, Q)				\
	({							\
		if ((F) != -1)					\
			queue_flag_set_unlocked(F, Q);		\
	})

# define queue_flag_clear_unlocked(F, Q)			\
	({							\
		if ((F) != -1)					\
			queue_flag_clear_unlocked(F, Q);	\
	})

# ifndef blk_queue_secdiscard
#  define blk_queue_secdiscard(q)   (0)
#  define QUEUE_FLAG_SECDISCARD    (-1)
# endif
#endif

#ifndef list_next_rcu
#define list_next_rcu(list)	(*((struct list_head **)(&(list)->next)))
#endif

#ifndef COMPAT_HAVE_SIMPLE_POSITIVE
#include <linux/dcache.h>
static inline int simple_positive(struct dentry *dentry)
{
        return dentry->d_inode && !d_unhashed(dentry);
}
#endif

#ifdef blk_queue_plugged
/* pre 7eaceac block: remove per-queue plugging
 * Code has been converted over to the new explicit on-stack plugging ...
 *
 * provide dummy struct blk_plug and blk_start_plug/blk_finish_plug,
 * so the main code won't be cluttered with ifdef.
 */
struct blk_plug { };
#if 0
static void blk_start_plug(struct blk_plug *plug) {};
static void blk_finish_plug(struct blk_plug *plug) {};
#else
#define blk_start_plug(plug) do { (void)plug; } while (0)
#define blk_finish_plug(plug) do { } while (0)
#endif
#endif

#if !(defined(COMPAT_HAVE_SHASH_DESC_ON_STACK) &&    \
      defined COMPAT_HAVE_SHASH_DESC_ZERO)
#include <crypto/hash.h>

#ifndef COMPAT_HAVE_SHASH_DESC_ON_STACK
#define SHASH_DESC_ON_STACK(shash, ctx)				  \
	char __##shash##_desc[sizeof(struct shash_desc) +	  \
		crypto_shash_descsize(ctx)] CRYPTO_MINALIGN_ATTR; \
	struct shash_desc *shash = (struct shash_desc *)__##shash##_desc
#endif

#ifndef COMPAT_HAVE_SHASH_DESC_ZERO
#ifndef barrier_data
#define barrier_data(ptr) barrier()
#endif
static inline void shash_desc_zero(struct shash_desc *desc)
{
	/* memzero_explicit(...) */
	memset(desc, 0, sizeof(*desc) + crypto_shash_descsize(desc->tfm));
	barrier_data(desc);
}
#endif
#endif

#ifdef COMPAT_HAVE_ATOMIC_DEC_IF_POSITIVE_LINUX
#include <linux/atomic.h>
#else
static inline int atomic_dec_if_positive(atomic_t *v)
{
        int c, old, dec;
        c = atomic_read(v);
        for (;;) {
                dec = c - 1;
                if (unlikely(dec < 0))
                        break;
                old = atomic_cmpxchg((v), c, dec);
                if (likely(old == c))
                        break;
                c = old;
        }
        return dec;
}
#endif

/* RDMA related */
#ifndef COMPAT_HAVE_IB_CQ_INIT_ATTR
#include <rdma/ib_verbs.h>

struct ib_cq_init_attr {
	unsigned int    cqe;
	int             comp_vector;
	u32             flags;
};

static inline struct ib_cq *
drbd_ib_create_cq(struct ib_device *device,
		  ib_comp_handler comp_handler,
		  void (*event_handler)(struct ib_event *, void *),
		  void *cq_context,
		  const struct ib_cq_init_attr *cq_attr)
{
	return ib_create_cq(device, comp_handler, event_handler, cq_context,
			    cq_attr->cqe, cq_attr->comp_vector);
}

#define ib_create_cq(DEV, COMP_H, EVENT_H, CTX, ATTR) \
	drbd_ib_create_cq(DEV, COMP_H, EVENT_H, CTX, ATTR)
#endif
/* RDMA */

#ifndef COMPAT_HAVE_PROC_CREATE_SINGLE
extern struct proc_dir_entry *proc_create_single(const char *name, umode_t mode,
		struct proc_dir_entry *parent,
		int (*show)(struct seq_file *, void *));
#endif

#ifdef COMPAT_HAVE_MAX_SEND_RECV_SGE
#define MAX_SGE(ATTR) min((ATTR).max_send_sge, (ATTR).max_recv_sge)
#else
#define MAX_SGE(ATTR) (ATTR).max_sge
#endif

#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT 9
#endif
#ifndef SECTOR_SIZE
#define SECTOR_SIZE (1 << SECTOR_SHIFT)
#endif

/* The declaration of arch_wb_cache_pmem() is in upstream in
   include/linux/libnvdimm.h. In RHEL7.6 it is in drivers/nvdimm/pmem.h.
   The kernel-devel package does not ship drivers/nvdimm/pmem.h.
   Therefore the declaration is here!
   Upstream moved it from drivers/nvdimm/pmem.h to libnvdimm.h with 4.14 */
#if defined(RHEL_MAJOR) && defined(RHEL_MINOR) && defined(CONFIG_ARCH_HAS_PMEM_API)
# if RHEL_MAJOR == 7 && RHEL_MINOR >= 6
void arch_wb_cache_pmem(void *addr, size_t size);
# endif
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0) && defined(CONFIG_ARCH_HAS_PMEM_API)
void arch_wb_cache_pmem(void *addr, size_t size);
#endif

#endif
