/*
  drbd_int.h
  Kernel module for 2.2.x/2.4.x Kernels

  This file is part of drbd by Philipp Reisner.

  Copyright (C) 1999-2003, Philipp Reisner <philipp.reisner@gmx.at>.
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
typedef unsigned long sector_t;
#endif
#define BH_SECTOR(BH) ( (BH)->b_blocknr * ((BH)->b_size>>9) )

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

#if defined(DBG_SPINLOCKS) && defined(__SMP__)
# define MUST_HOLD(lock) if(!spin_is_locked(lock)) { printk(KERN_ERR DEVICE_NAME ": Not holding lock! in %s\n", __FUNCTION__ ); }
#else 
# define MUST_HOLD(lock)
#endif

#define D_ASSERT(exp)  if (!(exp)) \
        printk(KERN_ERR DEVICE_NAME"%d: ASSERT( " #exp " ) in %s:%d\n", \
        (int)(mdev-drbd_conf),__FILE__,__LINE__)
        

// handy macro: DUMPP(somepointer) 
#define DUMPP(A) printk(KERN_ERR DEVICE_NAME "%d: "#A"= %p\n",(int)(mdev-drbd_conf),A);
#define DUMPLU(A) printk(KERN_ERR DEVICE_NAME "%d: "#A"= %lu\n",(int)(mdev-drbd_conf),A);

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
#define GFP_DRBD GFP_ATOMIC

/* these defines should go into blkdev.h 
   (if it will be ever includet into linus' linux) */
#define RQ_DRBD_NOTHING	  0x0000
#define RQ_DRBD_SENT	  0x0010
#define RQ_DRBD_WRITTEN   0x0020
#define RQ_DRBD_DONE      0x0030
#define RQ_DRBD_READ      0x0040

enum MetaDataFlags {
	MDF_Consistent   = 1,
	MDF_PrimaryInd   = 2,
	MDF_ConnectedInd = 4,
};
/* drbd_meta-data.c (still in drbd_main.c) */
enum MetaDataIndex { 
	Flags,          /* Consistency flag,connected-ind,primary-ind */ 
	HumanCnt,       /* human-intervention-count */
	TimeoutCnt,     /* timout-count */
	ConnectedCnt,   /* connected-count */
	ArbitraryCnt    /* arbitrary-count */
};

#define GEN_CNT_SIZE 5
#define DRBD_MD_MAGIC (DRBD_MAGIC+3) // 3nd incarnation of the file format.


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
  __u64       sector;    /* 64 bits sector number */
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
  __u64       p_size;  // size of disk
  __u64       u_size;  // user requested size
  __u32       state;
  __u32       protocol;
  __u32       version;
  __u32       gen_cnt[GEN_CNT_SIZE];
  __u32       bit_map_gen[GEN_CNT_SIZE];
}  __attribute((packed)) Drbd_Parameter_P;
MKPACKET(Drbd_Parameter_P)

typedef struct {
  __u64       sector;
  __u64       block_id;
  __u32       blksize;
} __attribute((packed)) Drbd_BlockAck_P;
MKPACKET(Drbd_BlockAck_P)

typedef struct {
  __u32       barrier;
  __u32       set_size;
}  __attribute((packed)) Drbd_BarrierAck_P;
MKPACKET(Drbd_BarrierAck_P)

typedef struct {
  __u64       sector;
  __u64       block_id;
  __u32       blksize;
} __attribute((packed)) Drbd_BlockRequest_P;
MKPACKET(Drbd_BlockRequest_P)

typedef enum { 
  Data, 
  DataReply,    
  RecvAck,      /* Used in protocol B */
  WriteAck,     /* Used in protocol C */
  Barrier,
  BarrierAck,  
  ReportParams,
  ReportBitMap,
  CStateChanged,
  Ping,
  PingAck,
  BecomeSyncTarget,
  BecomeSyncSource,
  BecomeSec,     /* Secondary asking primary to become secondary */
  WriteHint,     /* Used in protocol C to hint the secondary to call tq_disk */
  DataRequest,   /* Used to ask for a data block */
  RSDataRequest,   /* Used to ask for a data block */
  BlockInSync    /* Possible anser to CondDataRequest. No data will be send */
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

struct drbd_barrier;
struct drbd_request {
	struct list_head list;     // requests are chained to a barrier
	struct drbd_barrier *barrier; // The next barrier.
	struct buffer_head *bh;    // buffer head
	unsigned long sector;
	int size;
	int rq_status;
};

struct drbd_barrier {
	struct list_head requests; // requests before 
	struct drbd_barrier *next; // pointer to the next barrier
	int br_number;  // the barriers identifier.
	int n_req;      // number of requests attached before this barrier
};

typedef struct drbd_request drbd_request_t;

/* These Tl_epoch_entries may be in one of 4 lists:
   free_ee .... free entries
   active_ee .. data packet beeing written
   sync_ee .... syncer block beeing written
   done_ee .... block written, need to send ack packet
*/ 

struct Drbd_Conf;

struct Tl_epoch_entry {
	struct list_head list; 
	struct buffer_head* bh;
	u64    block_id;
	int   (*e_end_io) (struct Drbd_Conf*, struct Tl_epoch_entry *);
};

struct Pending_read {
	struct list_head list;
	union {
		struct buffer_head* bh;
		sector_t sector;
	} d;
	enum {
		Discard = 0,
		Application = 1,
		Resync = 2,
		AppAndResync = 3,
	} cause;
};

/* flag bits */
#define ISSUE_BARRIER      0
#define COLLECT_ZOMBIES    1
#define SEND_PING          2
#define WRITER_PRESENT     3
#define START_SYNC         4
#define DO_NOT_INC_CONCNT  5
#define WRITE_HINT_QUEUED  6
#define PARTNER_DISKLESS   7
#define SYNC_FINISHED      8
#define PROCESS_EE_RUNNING 9

struct send_timer_info {
	struct timer_list s_timeout; /* send timeout */
	struct Drbd_Conf *mdev;
	struct task_struct *task;
	volatile int timeout_happened;
	int via_msock;
	int restart;	
};


struct BitMap {
	kdev_t dev;
	unsigned long size;
	unsigned long* bm;
	unsigned long gs_bitnr;
	unsigned long gs_snr;
	spinlock_t bm_lock;
};

struct Drbd_Conf {
	struct net_config conf;
	struct syncer_config sync_conf;
        int do_panic;
	struct socket *sock;  /* for data/barrier/cstate/parameter packets */
	struct socket *msock; /* for ping/ack (metadata) packets */
	struct semaphore sock_mutex;
	struct semaphore msock_mutex;
 	struct semaphore ctl_mutex;
	kdev_t lo_device;
	struct file *lo_file;
	unsigned long lo_usize;   /* user provided size */
	unsigned long p_usize;    /* partner node's usize */
	unsigned long p_size;     /* partner's disk size */
	Drbd_State state;
	Drbd_CState cstate;
	wait_queue_head_t cstate_wait;
	wait_queue_head_t state_wait;
	Drbd_State o_state;
	unsigned long int la_size; // last agreed disk size
	unsigned int send_cnt;
	unsigned int recv_cnt;
	unsigned int read_cnt;
	unsigned int writ_cnt;
	atomic_t pending_cnt;
	atomic_t unacked_cnt;
	spinlock_t req_lock;
	spinlock_t tl_lock;
	struct drbd_barrier* newest_barrier;
	struct drbd_barrier* oldest_barrier;
        int    flags;
	struct timer_list a_timeout; /* ack timeout */
	struct send_timer_info* send_proc; /* about pid calling drbd_send */
	spinlock_t send_proc_lock;
	sector_t send_sector;      // block which is processed by send_data
	sector_t rs_left;     // blocks not up-to-date [unit sectors]
	sector_t rs_total;    // blocks to sync in this run [unit sectors]
	unsigned long rs_start;    // Syncer's start time [unit jiffies]
	sector_t rs_mark_left;// block not up-to-date at mark [unit sect.]
	unsigned long rs_mark_time;// marks's time [unit jiffies]
	spinlock_t rs_lock; // used to protect the rs_variables.
	spinlock_t bb_lock;
	struct Drbd_thread receiver;
	struct Drbd_thread dsender;
        struct Drbd_thread asender;
	wait_queue_head_t dsender_wait;
	struct BitMap* mbds_id;
	int open_cnt;
	u32 gen_cnt[GEN_CNT_SIZE];
	u32 bit_map_gen[GEN_CNT_SIZE];
	int epoch_size;
	spinlock_t ee_lock;
	struct list_head free_ee;   // available
	struct list_head active_ee; // IO in progress
	struct list_head sync_ee;   // IO in progress
	struct list_head done_ee;   // send ack
	struct list_head read_ee;   // IO in progress
	struct list_head rdone_ee;  // send result or CondRequest
	spinlock_t pr_lock;
	struct list_head app_reads;
	struct list_head resync_reads;
	int ee_vacant;
	int ee_in_use;
	wait_queue_head_t ee_wait;
	struct list_head busy_blocks;
	struct tq_struct write_hint_tq;
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
extern int tl_check_sector(struct Drbd_Conf *mdev, sector_t sector);
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
			 struct buffer_head *bh, u64 block_id);
extern int drbd_send_block(struct Drbd_Conf *mdev, int cmd,
			   struct buffer_head *bh, u64 block_id);
extern int drbd_send_dblock(struct Drbd_Conf *mdev, 
			    struct buffer_head *bh, u64 block_id);
extern int _drbd_send_barrier(struct Drbd_Conf *mdev);
extern int drbd_send_drequest(struct Drbd_Conf *mdev, int cmd, 
			      sector_t sector,int size, u64 block_id);
extern int drbd_send_insync(struct Drbd_Conf *mdev,sector_t sector,
			    u64 block_id);
extern int drbd_send_bitmap(struct Drbd_Conf *mdev);

extern int ds_check_sector(struct Drbd_Conf *mdev, sector_t sector);

/* drbd_req*/ 
#define ERF_NOTLD    2   /* do not call tl_dependence */
extern void drbd_end_req(drbd_request_t *req, int nextstate,int uptodate);
extern int drbd_make_request(request_queue_t *,int ,struct buffer_head *); 

/* drbd_fs.c: */
extern int drbd_determin_dev_size(struct Drbd_Conf*);
extern int drbd_set_state(int minor,Drbd_State newstate);
extern int drbd_ioctl(struct inode *inode, struct file *file,
		      unsigned int cmd, unsigned long arg);

/* drbd_meta-data.c (still in drbd_main.c) */

extern void drbd_md_write(struct Drbd_Conf *mdev);
extern void drbd_md_read(struct Drbd_Conf *mdev);
extern void drbd_md_inc(int minor, enum MetaDataIndex order);
extern int drbd_md_compare(int minor,Drbd_Parameter_P* partner);
extern int drbd_md_syncq_ok(int minor,Drbd_Parameter_P* partner,int have_good);

/* drbd_bitmap.c (still in drbd_main.c) */
#define SS_OUT_OF_SYNC (1)
#define SS_IN_SYNC     (0)
#define MBDS_SYNC_ALL (-2)
#define MBDS_DONE     (-3)
#define MBDS_PACKET_SIZE 4096

#define BM_BLOCK_SIZE_B  12  
#define BM_BLOCK_SIZE    (1<<BM_BLOCK_SIZE_B)

#define BM_IN_SYNC       0
#define BM_OUT_OF_SYNC   1

#if BITS_PER_LONG == 32
#define LN2_BPL 5
#elif BITS_PER_LONG == 64
#define LN2_BPL 6
#else
#error "LN2 of BITS_PER_LONG unknown!"
#endif

struct BitMap;
extern struct BitMap* bm_init(kdev_t dev);
extern int bm_resize(struct BitMap* sbm, unsigned long size_kb);
extern void bm_cleanup(struct BitMap* sbm);
extern int bm_set_bit(struct BitMap* sbm, sector_t sector, int size, int bit);
extern sector_t bm_get_sector(struct BitMap* sbm,int* size);
extern void bm_reset(struct BitMap* sbm);
extern void bm_fill_bm(struct BitMap* sbm,int value);
extern int bm_get_bit(struct BitMap* sbm, sector_t sector, int size);

extern struct Drbd_Conf *drbd_conf;
extern int minor_count;
extern void drbd_queue_signal(int signal,struct task_struct *task);

/* drbd_dsender.c */
extern int drbd_dsender(struct Drbd_thread *thi);
extern void drbd_dio_end_read(struct buffer_head *bh, int uptodate);
extern void drbd_start_resync(struct Drbd_Conf *mdev, Drbd_CState side);
extern unsigned long drbd_hash(struct buffer_head *bh);

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

static inline void inc_unacked(struct Drbd_Conf* mdev)
{
	atomic_inc(&mdev->unacked_cnt);
}

static inline void dec_unacked(struct Drbd_Conf* mdev)
{
	if(atomic_dec_and_test(&mdev->unacked_cnt))
		wake_up_interruptible(&mdev->state_wait);

	if(atomic_read(&mdev->unacked_cnt)<0)  /* CHK */
		printk(KERN_ERR DEVICE_NAME "%d: unacked_cnt <0 !!!\n",
		       (int)(mdev-drbd_conf));
}

static inline struct Drbd_Conf* drbd_lldev_to_mdev(kdev_t dev)
{
	int i;

	for (i=0; i<minor_count; i++) {
		if(drbd_conf[i].lo_device == dev) {
			return drbd_conf+i;
		}
	}
	printk(KERN_ERR DEVICE_NAME "X: lodev_to_mdev !!\n");
	return drbd_conf;
}

static inline void drbd_set_out_of_sync(struct Drbd_Conf* mdev,
					sector_t sector, int blk_size)
{
	mdev->rs_total += 
		bm_set_bit(mdev->mbds_id, sector, blk_size, SS_OUT_OF_SYNC);
}

static inline void drbd_set_in_sync(struct Drbd_Conf* mdev, 
				    sector_t sector, int blk_size)
{
	/* Is called by drbd_dio_end possibly from IRQ context, but
	   from other places in non IRQ */
	unsigned long flags=0; 
	bm_set_bit(mdev->mbds_id, sector, blk_size, SS_IN_SYNC);

	spin_lock_irqsave(&mdev->rs_lock,flags);
	mdev->rs_left -= blk_size >> 9;
	if( mdev->rs_left == 0 ) {
		spin_lock(&mdev->ee_lock); // IRQ lock already taken by rs_lock
		set_bit(SYNC_FINISHED,&mdev->flags);
		spin_unlock(&mdev->ee_lock);
                wake_up_interruptible(&mdev->dsender_wait);		
	}

	if(jiffies - mdev->rs_mark_time > HZ*10) {
		mdev->rs_mark_time=jiffies;
		mdev->rs_mark_left=mdev->rs_left;
	}
	spin_unlock_irqrestore(&mdev->rs_lock,flags);
}

extern int drbd_release_ee(struct Drbd_Conf* mdev,struct list_head* list);
extern void drbd_init_ee(struct Drbd_Conf* mdev);
extern void drbd_put_ee(struct Drbd_Conf* mdev,struct Tl_epoch_entry *e);
extern struct Tl_epoch_entry* drbd_get_ee(struct Drbd_Conf* mdev,
					  int may_sleep);
extern int _drbd_process_ee(struct Drbd_Conf *,struct list_head *);
extern int recv_resync_read(struct Drbd_Conf* mdev, struct Pending_read *pr, 
			    sector_t sector, int data_size);
extern int recv_dless_read(struct Drbd_Conf* mdev, struct Pending_read *pr, 
			   sector_t sector, int data_size);



/* drbd_proc.c  */
extern struct proc_dir_entry *drbd_proc;
extern int drbd_proc_get_info(char *, char **, off_t, int, int *, void *);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,10)
#define min_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })
#endif

#if !defined(CONFIG_HIGHMEM) && !defined(bh_kmap)
#define bh_kmap(bh)	((bh)->b_data)
#define bh_kunmap(bh)	do { } while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,10)
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
	sector_t sector;
};

static inline void bb_wait_prepare(struct Drbd_Conf *mdev,sector_t sector,
				   struct busy_block *bl)
{
	MUST_HOLD(&mdev->bb_lock);

	init_completion(&bl->event);
	bl->sector=sector;
	list_add(&bl->list,&mdev->busy_blocks);
}

static inline void bb_wait(struct busy_block *bl)
{
	// you may not hold bb_lock
	//printk(KERN_ERR DEVICE_NAME" sleeping because block %lu busy\n",
	//       bl->bnr);
	wait_for_completion(&bl->event);
}

static inline void bb_done(struct Drbd_Conf *mdev,sector_t sector)
{
	struct list_head *le;
	struct busy_block *bl;

	MUST_HOLD(&mdev->bb_lock);

	list_for_each(le,&mdev->busy_blocks) {
		bl = list_entry(le, struct busy_block,list);
		if(bl->sector == sector) {
			//printk(KERN_ERR DEVICE_NAME " completing %lu\n",bnr);
			list_del(le);
			complete(&bl->event);
			break;
		}
	}
}

static inline void drbd_init_bh(struct buffer_head *bh,
				int size)
{
	memset(bh, 0, sizeof(struct buffer_head));

	bh->b_list = BUF_LOCKED;
	init_waitqueue_head(&bh->b_wait);
	bh->b_size = size;
	atomic_set(&bh->b_count, 0);
	bh->b_state = (1 << BH_Mapped ); //has a disk mapping = dev & blocknr 
}


static inline void drbd_set_bh(struct buffer_head *bh,
			       sector_t sector,
			       int size,
			       kdev_t dev)
{
	bh->b_blocknr = sector / (size>>9);
	bh->b_size = size;
	bh->b_dev = dev;
}

