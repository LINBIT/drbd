/*
  drbd_int.h
  Kernel module for 2.2.x/2.4.x Kernels

  This file is part of drbd by Philipp Reisner.

  Copyright (C) 1999-2001, Philipp Reisner <philipp.reisner@gmx.at>.
        main author.

  Copyright (C) 2002, Lars Ellenberg <l.g.e@web.de>.
	some tidbits
 
  drbd is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2, or (at your option)
  any later version.
  
  drbd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with drbd; see the file COPYING.  If not, write to
  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#include <linux/types.h>
#include <linux/timer.h>
#include <linux/version.h>
#include <linux/list.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,7)
#define completion semaphore
#define init_completion(A) init_MUTEX_LOCKED(A)
#define wait_for_completion(A) down(A)
#define complete(A) up(A)
#else
#include <linux/completion.h>
#endif

/* Using the major_nr of the network block device
   prevents us from deadlocking with no request entries
   left on all_requests...
   look out for NBD_MAJOR in ll_rw_blk.c */

/*lge: this hack is to get rid of the compiler warnings about
 * 'do_nbd_request declared static but never defined'
 * whilst forcing blk.h defines on
 * though we probably do not need them, we do not use them...
 * would not work without LOCAL_END_REQUEST
 */
#define MAJOR_NR DRBD_MAJOR
#define DEVICE_ON(device)
#define DEVICE_OFF(device)
#define DEVICE_NR(device) (MINOR(device))
#define LOCAL_END_REQUEST
#include <linux/blk.h>
#define DRBD_MAJOR NBD_MAJOR

#ifdef DEVICE_NAME
#undef DEVICE_NAME
#endif
#define DEVICE_NAME "drbd"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define INITIAL_BLOCK_SIZE (1<<12)
#define DRBD_SIG SIGXCPU
#define ID_SYNCER (-1LL)

#ifdef DBG_ALL_SYMBOLS
# define STATIC
#else
# define STATIC static
#endif

#ifdef DBG_PRINTKS_RCV
# define DPRINTK(fmt, args... ) printk(KERN_DEBUG fmt, ##args)
#else
# define DPRINTK(...) 
#endif

/*lge: is this the right version dependency? */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,3,0)
#define get_bh(bh)      ((bh)->b_count++)
#define put_bh(bh)      ((bh)->b_count--)
/* drop_super is used in is_mounted().
 * FIXME: should it be replaced with something more useful?
 */
#define drop_super(sb)  ((void)0);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,2,18)
#define init_MUTEX_LOCKED( A )    (*(A)=MUTEX_LOCKED)
#define init_MUTEX( A )           (*(A)=MUTEX)
#define init_waitqueue_head( A )  (*(A)=0)
typedef struct wait_queue*  wait_queue_head_t;
#endif

/*
 * GFP_DRBD is used for allocations inside drbd_do_request.
 *
 * 2.4 kernels will probably remove the __GFP_IO check in the VM code,
 * so lets use GFP_ATOMIC for allocations.  For 2.2, we abuse the GFP_BUFFER 
 * flag to avoid __GFP_IO, thus avoiding the use of the atomic queue and 
 *  avoiding the deadlock.
 *
 * - marcelo
 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
#define GFP_DRBD GFP_ATOMIC
#else
#define GFP_DRBD GFP_BUFFER
#endif

/* these defines should go into blkdev.h 
   (if it will be ever includet into linus' linux) */
#define RQ_DRBD_NOTHING	  0xf100
#define RQ_DRBD_SENT	  0xf200
#define RQ_DRBD_WRITTEN   0xf300
#define RQ_DRBD_READ      0xf500

/* This is the layout for a packet on the wire! 
 * The byteorder is the network byte order!
 */
typedef struct {
  __u32       magic;
  __u16       command;
  __u16       length;
} __attribute((packed)) Drbd_Packet;

#define MKPACKET(NAME) \
typedef struct { \
  Drbd_Packet p; \
  NAME        h; \
}  __attribute((packed)) NAME##acket ;

typedef struct {
  __u64       block_nr;  /* 64 bits block number */
  __u64       block_id;  /* Used in protocol B&C for the address of the req. */
}  __attribute((packed)) Drbd_Data_P;
MKPACKET(Drbd_Data_P)

typedef struct {
  __u32       barrier;   /* may be 0 or a barrier number  */
  __u32       _fill;     /* Without the _fill gcc may add fillbytes on 
                            64 bit plaforms, but does not so an 32 bits... */
}  __attribute((packed)) Drbd_Barrier_P;
MKPACKET(Drbd_Barrier_P)

typedef struct {
  __u64       size;
  __u32       state;
  __u32       blksize;
  __u32       protocol;
  __u32       version;
  __u32       gen_cnt[5];
  __u32       bit_map_gen[5];
}  __attribute((packed)) Drbd_Parameter_P;
MKPACKET(Drbd_Parameter_P)

typedef struct {
  __u64       block_nr;
  __u64       block_id;
} __attribute((packed)) Drbd_BlockAck_P;
MKPACKET(Drbd_BlockAck_P)

typedef struct {
  __u32       barrier;
  __u32       set_size;
}  __attribute((packed)) Drbd_BarrierAck_P;
MKPACKET(Drbd_BarrierAck_P)

typedef struct {
  __u32       cstate;
}  __attribute((packed)) Drbd_CState_P;
MKPACKET(Drbd_CState_P)

typedef enum { 
  Data, 
  Barrier,
  RecvAck,      /* Used in protocol B */
  WriteAck,     /* Used in protocol C */
  BarrierAck,  
  ReportParams,
  CStateChanged,
  Ping,
  PingAck,
  StartSync,     /* Secondary asking primary to start sync */ 
  BecomeSec,     /* Secondary asking primary to become secondary */
  SetConsistent, /* Syncer run was successfull */
  WriteHint      /* Used in protocol C to hint the secondary to call tq_disk */
} Drbd_Packet_Cmd;


typedef enum { 
	Running,
	Exiting,
	Restarting
} Drbd_thread_state; 

struct Drbd_thread {
	struct task_struct *task;
	struct semaphore mutex;
	int t_state;
	int (*function) (struct Drbd_thread *);
	int minor;
};

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,0)
struct drbd_request_struct {
        struct buffer_head* bh; /* bh waiting for io_completion */
        int rq_status;
};

typedef struct drbd_request_struct drbd_request_t;
#define GET_SECTOR(A) ((A)->bh->b_rsector)
#else
typedef struct request drbd_request_t;
#define GET_SECTOR(A) ((A)->sector)
#endif

struct tl_entry {
        drbd_request_t* req;
        unsigned long sector;
};

/* These Tl_epoch_entries may be in one of 4 lists:
   free_ee .... free entries
   active_ee .. data packet beeing written
   sync_ee .... syncer block beeing written
   done_ee .... block written, need to send ack packet
*/ 
struct Tl_epoch_entry {
	struct list_head list; 
	struct buffer_head* bh;
	u64    block_id;
};

/* flag bits */
#define ISSUE_BARRIER     0
#define COLLECT_ZOMBIES   1
#define SEND_PING         2
#define WRITER_PRESENT    3
/*                        4   */
#define DO_NOT_INC_CONCNT 5
#define WRITE_HINT_QUEUED 6

struct send_timer_info {
	struct timer_list s_timeout; /* send timeout */
	struct Drbd_Conf *mdev;
	struct task_struct *task;
	volatile int timeout_happened;
	int via_msock;
	int restart;	
};

struct ds_buffer;

struct Drbd_Conf {
	struct net_config conf;
        int do_panic;
	struct socket *sock;  /* for data/barrier/cstate/parameter packets */
	struct socket *msock; /* for ping/ack (metadata) packets */
	kdev_t lo_device;
	struct file *lo_file;
	int lo_usize;   /* user provided size */
	int blk_size_b;
	Drbd_State state;
	Drbd_CState cstate;
	wait_queue_head_t cstate_wait;
	wait_queue_head_t state_wait;
	Drbd_State o_state;
	unsigned int send_cnt;
	unsigned int recv_cnt;
	unsigned int read_cnt;
	unsigned int writ_cnt;
	atomic_t pending_cnt;
	atomic_t unacked_cnt;
	spinlock_t req_lock;
	rwlock_t tl_lock;
	struct tl_entry* tl_end;
	struct tl_entry* tl_begin;
	struct tl_entry* transfer_log;
        int    flags;
	struct timer_list a_timeout; /* ack timeout */
	struct semaphore send_mutex;
	struct semaphore ctl_mutex;    /* for ioctl */
	struct send_timer_info* send_proc; /* about pid calling drbd_send */
	unsigned long send_block; // block which is processed by send_data
	spinlock_t send_proc_lock;
	unsigned long synced_to;	/* Unit: sectors (512 Bytes) */
	unsigned long resync_mark;       // for procfs
	unsigned long resync_mark_cnt;   // syncer
	unsigned long resync_mark_start; // progress bars
	struct ds_buffer *syncer_b;
	spinlock_t bb_lock;
	struct Drbd_thread receiver;
	struct Drbd_thread syncer;
        struct Drbd_thread asender;
	struct BitMap* mbds_id;
	int open_cnt;
	u32 gen_cnt[5];
	u32 bit_map_gen[5];
	int epoch_size;
	spinlock_t ee_lock;
	struct list_head free_ee;  
	struct list_head active_ee;
	struct list_head sync_ee;  
	struct list_head done_ee;
	int ee_vacant;
	int ee_in_use;
	wait_queue_head_t ee_wait;
	struct list_head busy_blocks;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	struct tq_struct write_hint_tq;
#endif
#ifdef ES_SIZE_STATS
	unsigned int essss[ES_SIZE_STATS];
#endif  
};

/* drbd_main.c: */
extern void drbd_thread_start(struct Drbd_thread *thi);
extern void _drbd_thread_stop(struct Drbd_thread *thi, int restart, int wait);
extern void drbd_free_resources(int minor);
extern int drbd_log2(int i);
extern void tl_release(struct Drbd_Conf *mdev,unsigned int barrier_nr,
		       unsigned int set_size);
extern void tl_clear(struct Drbd_Conf *mdev);
extern int tl_dependence(struct Drbd_Conf *mdev, drbd_request_t * item);
extern int tl_check_sector(struct Drbd_Conf *mdev, unsigned long sector);
extern void drbd_free_sock(int minor);
/*extern int drbd_send(struct Drbd_Conf *mdev, Drbd_Packet_Cmd cmd, 
		     Drbd_Packet* header, size_t header_size, 
		     void* data, size_t data_size);*/
extern int drbd_send_param(struct Drbd_Conf *mdev);
extern int drbd_send_cmd(struct Drbd_Conf *mdev,Drbd_Packet_Cmd cmd, 
			 int via_msock);
extern int drbd_send_cstate(struct Drbd_Conf *mdev);
extern int drbd_send_b_ack(struct Drbd_Conf *mdev, u32 barrier_nr,
			   u32 set_size);
extern int drbd_send_ack(struct Drbd_Conf *mdev, int cmd, 
			 unsigned long block_nr,u64 block_id);
extern int drbd_send_block(struct Drbd_Conf *mdev, struct buffer_head *bh, 
			  u64 block_id);
extern int _drbd_send_barrier(struct Drbd_Conf *mdev);


extern int ds_check_block(struct Drbd_Conf *mdev, unsigned long bnr);

/* drbd_req*/ 
extern void drbd_end_req(drbd_request_t *req, int nextstate,int uptodate);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,0)
extern int drbd_make_request(request_queue_t *,int ,struct buffer_head *); 
#else
extern void drbd_do_request(void);
#endif	

/* drbd_fs.c: */
extern int drbd_set_state(int minor,Drbd_State newstate);
extern int drbd_ioctl(struct inode *inode, struct file *file,
		      unsigned int cmd, unsigned long arg);

/* drbd_meta-data.c (still in drbd_main.c) */
enum MetaDataIndex { 
	Consistent,     /* Consistency flag, */ 
	HumanCnt,       /* human-intervention-count */
	ConnectedCnt,   /* connected-count */
	ArbitraryCnt,   /* arbitrary-count */
	PrimaryInd,     /* primary-indicator, updated in drbd_md_write */
	MagicNr        
};

extern void drbd_md_write(int minor);
extern void drbd_md_read(int minor);
extern void drbd_md_inc(int minor, enum MetaDataIndex order);
extern int drbd_md_compare(int minor,Drbd_Parameter_P* partner);
extern int drbd_md_syncq_ok(int minor,Drbd_Parameter_P* partner,int have_good);

/* drbd_bitmap.c (still in drbd_main.c) */
#define SS_OUT_OF_SYNC (1)
#define SS_IN_SYNC     (0)
#define MBDS_SYNC_ALL (-2)
#define MBDS_DONE     (-3)

struct BitMap;
extern struct BitMap* bm_init(kdev_t dev);
extern void bm_cleanup(void* bm_id);
extern void bm_set_bit(struct BitMap* sbm,unsigned long blocknr,int ln2_block_size, int bit);
extern unsigned long bm_get_blocknr(struct BitMap* sbm,int ln2_block_size);
extern void bm_reset(struct BitMap* sbm,int ln2_block_size);

extern struct Drbd_Conf *drbd_conf;
extern int minor_count;
extern void drbd_queue_signal(int signal,struct task_struct *task);

static inline void drbd_thread_stop(struct Drbd_thread *thi)
{
	_drbd_thread_stop(thi,FALSE,TRUE);
}

static inline void drbd_thread_restart_nowait(struct Drbd_thread *thi)
{
	_drbd_thread_stop(thi,TRUE,FALSE);
}

static inline void set_cstate(struct Drbd_Conf* mdev,Drbd_CState cs)
{
	mdev->cstate = cs;
	wake_up_interruptible(&mdev->cstate_wait);	
}

static inline void tl_init(struct Drbd_Conf *mdev)
{
	mdev->tl_begin = mdev->transfer_log;
	mdev->tl_end = mdev->transfer_log;
}

static inline void inc_pending(struct Drbd_Conf* mdev)
{
	atomic_inc(&mdev->pending_cnt);
	if(mdev->conf.timeout ) {
		mod_timer(&mdev->a_timeout,
			  jiffies + mdev->conf.timeout * HZ / 10);
	}
}

static inline void dec_pending(struct Drbd_Conf* mdev)
{
	if(atomic_dec_and_test(&mdev->pending_cnt))
		wake_up_interruptible(&mdev->state_wait);

	if(atomic_read(&mdev->pending_cnt)<0)  /* CHK */
		printk(KERN_ERR DEVICE_NAME "%d: pending_cnt <0 !!!\n",
		       (int)(mdev-drbd_conf));
		
	if(mdev->conf.timeout ) {
		if(atomic_read(&mdev->pending_cnt) > 0) {
			mod_timer(&mdev->a_timeout,
				  jiffies + mdev->conf.timeout 
				  * HZ / 10);
		} else {
			del_timer(&mdev->a_timeout);
		}
	}	
}

extern int drbd_release_ee(struct Drbd_Conf* mdev,struct list_head* list);
extern void drbd_init_ee(struct Drbd_Conf* mdev);

/* drbd_proc.c  */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
extern struct proc_dir_entry *drbd_proc;
extern int drbd_proc_get_info(char *, char **, off_t, int, int *, void *);
#else
extern struct proc_dir_entry drbd_proc_dir;
extern int drbd_proc_get_info(char *, char **, off_t, int, int);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,10)
#define min_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
#define SIGSET_OF(P) (&(P)->signal)
#else
#define SIGSET_OF(P) (&(P)->pending.signal)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
#define del_timer_sync(A) del_timer(A)
//typedef	struct wait_queue wait_queue_t;
#ifndef init_waitqueue_entry
#define init_waitqueue_entry(A,B) (A)->task=(B)
#endif
#define wq_write_lock_irqsave(A,B) write_lock_irqsave(A,B)
#define wq_write_lock_irq(A) write_lock_irq(A)
#define wq_write_unlock(A) write_unlock(A)
#define wq_write_unlock_irqrestore(A,B) write_unlock_irqrestore(A,B)
#endif

#ifdef __arch_um__
#define waitpid(A,B,C) 0
#endif

#if !defined(CONFIG_HIGHMEM) && !defined(bh_kmap)
#define bh_kmap(bh)	((bh)->b_data)
#define bh_kunmap(bh)	do { } while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,13)
#define MODULE_LICENSE(L) 
#endif

#ifndef list_for_each
#define list_for_each(pos, head) \
        for(pos = (head)->next; pos != (head); pos = pos->next)
#endif

/*
  There was a race condition between the syncer's and applications' write
  requests on the primary node.

  E.g:

  1) Syncer issues a read request for 4711
  2) Application write for 4711
  2a) 4711(new) is sent via the socket
  2b) 4711(new) is handed over the the IO subsystem
  3) Syncer gets 4711(old)
  4) Syncer sends 4711(old)
  5) 4711(new) is written to primary disk.

  The secondary gets the 4711(new) first, followed by 4711(old) and
  write 4711(old) to its disk.

  Therefore 

  bb_wait(),bb_done(),ds_check_block() and tl_check_sector()

 */

struct busy_block {
	struct list_head list; 
	struct completion event;
	unsigned long bnr;
};

static inline void bb_wait(struct Drbd_Conf *mdev,unsigned long bnr,
			   unsigned long* flags)
{
	struct busy_block bl;

	init_completion(&bl.event);
	bl.bnr=bnr;
	list_add(&bl.list,&mdev->busy_blocks);
	spin_unlock_irqrestore(&mdev->bb_lock,*flags);

      //printk(KERN_ERR DEVICE_NAME " sleeping because block %lu busy\n",bnr);
	wait_for_completion(&bl.event);
	spin_lock_irqsave(&mdev->bb_lock,*flags);
}

static inline void bb_done(struct Drbd_Conf *mdev,unsigned long bnr)
{
	struct list_head *le;
	struct busy_block *bl;

	list_for_each(le,&mdev->busy_blocks) {
		bl = list_entry(le, struct busy_block,list);
		if(bl->bnr == bnr) {
			//printk(KERN_ERR DEVICE_NAME " completing %lu\n",bnr);
			complete(&bl->event);
			list_del(le);
			break;
		}
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
typedef char page_t [4096];

#define alloc_page(A) ((page_t*)__get_free_page((A)))
#define alloc_pages(A,B) ((page_t*)__get_free_pages((A),(B)))

#define drbd_free_page(A) free_page((unsigned long)A) 
#define drbd_free_pages(A,B) free_pages((unsigned long)A,B) 

static inline void set_bh_page(struct buffer_head *bh, 
			       page_t *page, 
			       unsigned long offset)
{
	bh->b_data = ((char *)page) + offset;
}

static inline void drbd_init_bh(struct buffer_head *bh,
				int size,
				void (*handler)(struct buffer_head*,int))
{
	memset(bh, 0, sizeof(struct buffer_head));

	bh->b_list = BUF_LOCKED;
	bh->b_end_io = handler;
	init_waitqueue_head(&bh->b_wait);
	bh->b_size = size;
	// bh->b_state = 0; memset(bh,0 ... does the job :)
}

static inline void submit_bh(int rw, struct buffer_head * bh)
{
	clear_bit(BH_Lock, &bh->b_state); //ll_rw_block() wants to lock it
	ll_rw_block(rw, 1, &bh);
}

#else
typedef struct page page_t;

#define drbd_free_page(A) __free_page(A) 
#define drbd_free_pages(A,B) __free_pages(A,B) 

static inline void drbd_init_bh(struct buffer_head *bh,
				int size,
				void (*handler)(struct buffer_head*,int))
{
	memset(bh, 0, sizeof(struct buffer_head));

	bh->b_list = BUF_LOCKED;
	bh->b_end_io = handler;
	init_waitqueue_head(&bh->b_wait);
	bh->b_size = size;
	atomic_set(&bh->b_count, 0);
	bh->b_state = (1 << BH_Mapped ); //has a disk mapping = dev & blocknr 
}

#endif

static inline void drbd_set_bh(struct buffer_head *bh,
			       unsigned long block,
			       kdev_t dev)
{
	bh->b_blocknr=block;
	bh->b_dev = dev;
}


