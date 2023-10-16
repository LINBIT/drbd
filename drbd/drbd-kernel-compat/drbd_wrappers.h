#ifndef _DRBD_WRAPPERS_H
#define _DRBD_WRAPPERS_H

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
# error "At least kernel 3.10.0 (with patches) required"
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

/* introduced in v4.11-rc3-93-ged067d4a859f linux/kernel.h: Add ALIGN_DOWN macro */
#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, a)       __ALIGN_KERNEL((x) - ((a) - 1), (a))
#endif

/* introduced in v3.13-4220-g89a0714106aa */
#ifndef U32_MAX
#define U32_MAX ((u32)~0U)
#endif
#ifndef S32_MAX
#define S32_MAX ((s32)(U32_MAX>>1))
#endif

/* introduced in v3.18-rc3-2-g230fa253df63 */
#ifndef READ_ONCE
#define READ_ONCE ACCESS_ONCE
#endif
/* introduced in v3.19-rc4-1-g43239cbe79fc */
#ifndef WRITE_ONCE
#define WRITE_ONCE(x, val) do { *(volatile typeof(x) *)&(x) = (val); } while (0)
#endif

/* introduced in v4.3-8058-g71baba4b92dc */
#ifndef __GFP_RECLAIM
#define __GFP_RECLAIM __GFP_WAIT
#endif

/* introduced in v4.14-rc8-66-gf54bb2ec02c8 */
#ifndef lockdep_assert_irqs_disabled
#define lockdep_assert_irqs_disabled() do { } while (0)
#endif

/* introduced in v5.0-6417-g2bdde670beed */
#ifndef DEFINE_DYNAMIC_DEBUG_METADATA
#define DEFINE_DYNAMIC_DEBUG_METADATA(D, F) const char *D = F
#define __dynamic_pr_debug(D, F, args...) do { (void)(D); if (0) printk(F, ## args); } while(0)
#define DYNAMIC_DEBUG_BRANCH(D) false
#endif

/* introduced in v4.7-11559-g9049fc745300 */
#ifndef DYNAMIC_DEBUG_BRANCH
#define DYNAMIC_DEBUG_BRANCH(descriptor) \
	(unlikely(descriptor.flags & _DPRINTK_FLAGS_PRINT))
#endif

/* introduced in v4.10-rc3-157-g1e24edca0557 */
#ifndef KREF_INIT
#define KREF_INIT(N) { ATOMIC_INIT(N) }
#endif

/* introduced in v4.4-rc2-61-ga55bbd375d18 */
#ifndef idr_for_each_entry_continue
#define idr_for_each_entry_continue(idp, entry, id)			\
	for (entry = (typeof(entry))idr_get_next((idp), &(id));		\
	     entry;							\
	     ++id, entry = (typeof(entry))idr_get_next((idp), &(id)))
#endif

/* introduced in v4.17-rc7-25-gead9ad7253f4 */
#ifndef list_for_each_entry_from_rcu
#define list_for_each_entry_from_rcu(pos, head, member)			\
	for (; &(pos)->member != (head);					\
		pos = list_entry_rcu(pos->member.next, typeof(*(pos)), member))
#endif

/* introduced in v3.13-rc2-4-g462225ae47d7 */
#ifndef RCU_INITIALIZER
#define RCU_INITIALIZER(v) (typeof(*(v)) *)(v)
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

/* synopsis of blkdev_issue_zeroout changed a few times */
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

#ifndef COMPAT_HAVE_SIMPLE_POSITIVE
#include <linux/dcache.h>
static inline int simple_positive(struct dentry *dentry)
{
        return dentry->d_inode && !d_unhashed(dentry);
}
#endif

#if !(defined(COMPAT_HAVE_SHASH_DESC_ON_STACK) &&    \
      defined COMPAT_HAVE_SHASH_DESC_ZERO)
#include <crypto/hash.h>

/* introduced in a0a77af14117 (v3.17-9284) */
#ifndef COMPAT_HAVE_SHASH_DESC_ON_STACK
#define SHASH_DESC_ON_STACK(shash, ctx)				  \
	char __##shash##_desc[sizeof(struct shash_desc) +	  \
		crypto_shash_descsize(ctx)] CRYPTO_MINALIGN_ATTR; \
	struct shash_desc *shash = (struct shash_desc *)__##shash##_desc
#endif

/* introduced in e67ffe0af4d4 (v4.5-rc1-24) */
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

/* made conveniently accessible in v4.16-rc2-252-g233bde21aa43 */
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

#ifndef list_last_entry
#define list_last_entry(ptr, type, member) \
        list_entry((ptr)->prev, type, member)
#endif

#endif
