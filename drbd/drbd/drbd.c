/*
  drbd.c
  Kernel module for 2.2.x/2.4.x Kernels
  
  This file is part of drbd by Philipp Reisner.

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

#ifdef HAVE_AUTOCONF
#include <linux/autoconf.h>
#endif
#ifdef CONFIG_MODVERSIONS
#include <linux/modversions.h>
#endif  

#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/slab.h>
#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>

#include "drbd.h"


/* #define MAJOR_NR 240 */
#define MAJOR_NR 43
/* Using the major_nr of the network block device
   prevents us from deadlocking with no request entries
   left on all_requests...
   look out for NBD_MAJOR in ll_rw_blk.c */

#define DEVICE_ON(device)
#define DEVICE_OFF(device)
#define DEVICE_NR(device) (MINOR(device))
#include <linux/blk.h>

#if LINUX_VERSION_CODE > 0x20300
#include <linux/blkpg.h>
#else
#define init_MUTEX_LOCKED( A )   (*(A)=MUTEX_LOCKED)
#define init_MUTEX( A )          (*(A)=MUTEX)
#endif

#ifdef DEVICE_NAME
#undef DEVICE_NAME
#endif
#define DEVICE_NAME "drbd"

#define DRBD_SIG SIGXCPU

struct Drbd_thread {
  int                      pid;
  struct semaphore         sem;
  int                      exit;
  int                      (*function)(void*);
  int                      minor;
};

struct Drbd_Conf {
  struct ioctl_drbd_config conf;
  struct socket*           sock;
  kdev_t		   lo_device;
  struct file*             lo_file;
  int                      blk_size_b;
  Drbd_State               state;
  Drbd_CState              cstate;
  u64*                     transfer_log;
  u64*                     tl_begin;
  u64*                     tl_end;
  spinlock_t               tl_lock;
  int                      send_cnt;
  int                      recv_cnt;
  struct timer_list        s_timeout_t;
  struct semaphore         send_mutex;
  unsigned long	           synced_to; /* Unit: sectors (512 Bytes) */
  struct Drbd_thread       receiver;
  struct Drbd_thread       syncer;
};

struct Drbd_buffer_head {
  struct buffer_head bh;
  struct Drbd_Conf* mdev;
};


int drbd_send(int minor,Drbd_Packet_Cmd cmd,int len,
	       unsigned long sect_nr,void * data);
int drbd_send_param(int minor,int cmd);
void drbd_thread_start(struct Drbd_thread* thi);
#define drbd_thread_stop(A)     _drbd_thread_stop(A,FALSE)
#define drbd_thread_restart(A)  _drbd_thread_stop(A,TRUE)
void _drbd_thread_stop(struct Drbd_thread* thi,int restart);

int drbdd_init(void *arg);
int drbd_syncer(void *arg);
void drbd_free_resources(int minor);
#if LINUX_VERSION_CODE > 0x20300
/*static*/ int drbd_proc_get_info(char *, char ** , off_t ,int , int *, void *);
#else
/*static*/ int drbd_proc_get_info(char * , char ** , off_t ,int , int );
#endif
/*static*/ void drbd_dio_end(struct buffer_head *bh, int uptodate);

int drbd_init( void );
/*static*/ int drbd_open(struct inode *inode, struct file *file);
/*static*/ int drbd_close(struct inode *inode, struct file *file);
/*static*/ int drbd_ioctl(struct inode *inode, struct file *file, 
		      unsigned int cmd, unsigned long arg);
/*static*/ int drbd_fsync(struct file * file, struct dentry * dentry);
/*static*/ void drbd_do_request( void ); 

#ifdef DEVICE_REQUEST
#undef DEVICE_REQUEST
#endif
#define DEVICE_REQUEST drbd_do_request


#define MODULE_NAME DEVICE_NAME": "
#define MINOR_COUNT 2

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

MODULE_AUTHOR("Philipp Reisner <e9525415@stud2.tuwien.ac.at>");
MODULE_DESCRIPTION("drbd - Network block device");

/*static*/ int drbd_blocksizes[MINOR_COUNT];
/*static*/ int drbd_sizes[MINOR_COUNT];
/*static*/ struct Drbd_Conf drbd_conf[MINOR_COUNT];

/*static*/ struct file_operations drbd_fops =
{
	NULL,                   /* lseek - default */
	block_read,             /* read - general block-dev read */
	block_write,            /* write - general block-dev write */
	NULL,                   /* readdir - bad */
	NULL,                   /* poll */
	drbd_ioctl,             /* ioctl */
	NULL,                   /* mmap */
	drbd_open,              /* open */
	NULL,			/* flush */
	drbd_close,             /* release */
	drbd_fsync,             /* fsync */
	NULL,			/* fasync */
	NULL,			/* check_media_change */
	NULL,			/* revalidate */
	NULL                    /* lock */
};

/************************* PROC FS stuff begin */
#include <linux/proc_fs.h>

#if LINUX_VERSION_CODE > 0x20300 
struct proc_dir_entry *drbd_proc;
#else
struct proc_dir_entry drbd_proc_dir = 
{
  0, 4, "drbd",
  S_IFREG | S_IRUGO , 1, 0, 0,
  0, NULL,
  &drbd_proc_get_info, NULL,
  NULL,
  NULL, NULL
};
#endif


struct request* my_all_requests = NULL;

#if LINUX_VERSION_CODE > 0x20300 
/*static*/ int drbd_proc_get_info(char * buf , char ** start, off_t offset,
				  int len, int *unused, void *data)	
#else
/*static*/ int drbd_proc_get_info(char * buf , char ** start, off_t offset, 
			      int len, int unused)
#endif
{
  int rlen,i;

  static const char* cstate_names[6] =
  {
    "Unconfigured",
    "Unconnected", 
    "WFConnection",
    "WFReportParams",
    "Syncing", 
    "Connected" 
  };
  static const char* state_names[2] =
  {
    "Primary", 
    "Secondary"
  };


  rlen = sprintf(buf,
		 "version       : %d\n\n",
		 MOD_VERSION);    

  for (i = 0; i < MINOR_COUNT; i++) 
    {
      rlen = rlen + sprintf(buf+rlen,"%d: cs:%s st:%s s:%d r:%d\n",
			    i,
			    cstate_names[drbd_conf[i].cstate],
			    state_names[drbd_conf[i].state],
			    drbd_conf[i].send_cnt,
			    drbd_conf[i].recv_cnt);
    }

#if DBG 

  if(my_all_requests != NULL)
  {
    char major_to_letter[256];
    char current_letter='a',l;
    int m;

    for(i=0;i<256;i++)
      {
	major_to_letter[i]=0;
      }

    rlen = rlen + sprintf(buf+rlen,"\n");
    
    for(i=0;i<NR_REQUEST;i++)
      {
	if(my_all_requests[i].rq_status==RQ_INACTIVE)
	  {
	    l='E';
	  }
	else
	  {
	    m = MAJOR(my_all_requests[i].rq_dev);
	    l = major_to_letter[m];
	    if(l == 0)
	      {
		l=major_to_letter[m]=current_letter++;
	      }
	  }
	rlen = rlen + sprintf(buf+rlen,"%c",l);
      }

    rlen = rlen + sprintf(buf+rlen,"\n");
    
    for(i=0;i<256;i++)
      {
	l = major_to_letter[i];
	if( l != 0 )
	  rlen = rlen + sprintf(buf+rlen,"%c: %d\n",l,i);
      }
  }
#endif

  return rlen;
}

/* PROC FS stuff end */

/************************* The transfer log start */
/* I am not shure if the irqsave spin_lock is required ... */
inline void tl_add(struct Drbd_Conf* mdev,u64 new_nr)
{
  unsigned long flags;
  spin_lock_irqsave(&mdev->tl_lock, flags);

  *mdev->tl_end = cpu_to_be64(new_nr);
  mdev->tl_end++;

  if(mdev->tl_end == mdev->transfer_log + mdev->conf.tl_size) 
    mdev->tl_end=mdev->transfer_log;

  if(mdev->tl_end == mdev->tl_begin)
      printk( KERN_ERR DEVICE_NAME ": transferlog too small!! \n");
  spin_unlock_irqrestore(&mdev->tl_lock, flags);
}     

inline void tl_init(struct Drbd_Conf* mdev)
{
  mdev->tl_begin = mdev->transfer_log;
  mdev->tl_end   = mdev->transfer_log;
}

inline void tl_release(struct Drbd_Conf* mdev,u64 old_nr,int rp)
{
  static int count = 0;
  unsigned long flags;
  spin_lock_irqsave(&mdev->tl_lock, flags);

  if(*mdev->tl_begin != old_nr && count < 30)
    {
      printk( KERN_ERR DEVICE_NAME ": WRITE-order!! was=%ld is=%ld @%d\n",
	      (unsigned long)be64_to_cpu(*mdev->tl_begin),
	      (unsigned long)be64_to_cpu(old_nr),rp);
      count++;
    }

  mdev->tl_begin++;

  if(mdev->tl_begin == mdev->transfer_log + mdev->conf.tl_size) 
    mdev->tl_begin=mdev->transfer_log;

  spin_unlock_irqrestore(&mdev->tl_lock, flags);
} 

inline void tl_send_ack(int minor, u64 sector)
{
  int len;
  struct Drbd_Conf* mdev = &drbd_conf[minor];
  unsigned long flags;

  tl_add(mdev, sector);

  spin_lock_irqsave(&mdev->tl_lock, flags);

  if(mdev->tl_end >= mdev->tl_begin) len = mdev->tl_end - mdev->tl_begin;
  else len = mdev->conf.tl_size - (mdev->tl_begin - mdev->tl_end);
  spin_unlock_irqrestore(&mdev->tl_lock, flags);

  if(len > mdev->conf.tl_size/2  )
    {
      u64 *begin, *end;
      /* need to send an ack packet */
      printk( KERN_ERR DEVICE_NAME ": sending ack! for %d packets\n",len);

      spin_lock_irqsave(&mdev->tl_lock, flags);
      begin=mdev->tl_begin;
      end=mdev->tl_end;
      mdev->tl_begin=mdev->tl_end;
      spin_unlock_irqrestore(&mdev->tl_lock, flags);
      /* The first send might sleep thus I have to have my own begin&end */

      if(end >= begin)
	{
	  drbd_send(minor,Ack,len*sizeof(u64),0,begin);
	}
      else
	{
	  drbd_send(minor,Ack,
		    (mdev->transfer_log + mdev->conf.tl_size - begin)*
		    sizeof(u64),
		    0,begin);
	  drbd_send(minor,Ack,
		    (end - mdev->transfer_log) *
		    sizeof(u64),
		    0,mdev->transfer_log);  
	}      
    }
}

/* Transfer log end */ 

int drbd_log2(int i)
{
  int bits=0;
  while(i != 1) {
    bits++;
    i >>= 1;
  }
  return bits;
}


void drbd_send_timeout(unsigned long arg)
{
  struct task_struct * p = (struct task_struct *) arg;

  printk( KERN_ERR DEVICE_NAME ": timeout detected!\n");

  send_sig_info(DRBD_SIG, NULL, p);
}

int drbd_send(int minor,Drbd_Packet_Cmd cmd,int len,
	      unsigned long sect_nr,void * data)
{
  mm_segment_t oldfs;
  struct msghdr msg;
  struct iovec iov[2];
  Drbd_Packet packet_header;
  int err;

  if(! drbd_conf[minor].sock) return -1000;

  down( &drbd_conf[minor].send_mutex );
  /* Without this sock_sendmsg() somehow mixes bytes :-) */

  packet_header.magic = cpu_to_be32(DRBD_MAGIC);
  packet_header.command = cpu_to_be16(cmd);
  packet_header.length = cpu_to_be16(len);
  packet_header.block_nr = cpu_to_be64(sect_nr);

  iov[0].iov_base=(void*)&packet_header;
  iov[0].iov_len=sizeof(packet_header);
  iov[1].iov_base=data;
  iov[1].iov_len=len;

  msg.msg_iov=iov;
  msg.msg_iovlen=2;
  msg.msg_control=NULL;
  msg.msg_controllen=0;
  msg.msg_name=0;
  msg.msg_namelen=0;
  msg.msg_flags = MSG_NOSIGNAL;
  
  if(drbd_conf[minor].conf.timeout)
    {
      drbd_conf[minor].s_timeout_t.data = (unsigned long) current;
      drbd_conf[minor].s_timeout_t.expires = 
	jiffies + drbd_conf[minor].conf.timeout * HZ / 10 ; 
      add_timer(&drbd_conf[minor].s_timeout_t);
    }

  lock_kernel();
  oldfs = get_fs(); set_fs(KERNEL_DS);
  err = sock_sendmsg(drbd_conf[minor].sock, &msg,
		     iov[1].iov_len+sizeof(packet_header));
  set_fs(oldfs);
  unlock_kernel();

  if(drbd_conf[minor].conf.timeout)
    {
      del_timer(&drbd_conf[minor].s_timeout_t);

      spin_lock_irq(&current->sigmask_lock);
      if(sigismember(&current->signal,DRBD_SIG))
	{
	  sigdelset(&current->signal,DRBD_SIG);
	  recalc_sigpending(current);
	  spin_unlock_irq(&current->sigmask_lock);
	  printk( KERN_ERR DEVICE_NAME ": send timed out!!\n");
	  
	  drbd_thread_restart(&drbd_conf[minor].receiver);
	}
      else spin_unlock_irq(&current->sigmask_lock);
    }

  if(err == len+sizeof(packet_header) )
    {
      if(len >= 512 && be16_to_cpu(packet_header.command) == 0)
	tl_add(&drbd_conf[minor],sect_nr);
    }
  else
    {
      printk( KERN_ERR DEVICE_NAME ": sock_sendmsg returned %d\n",err);
    }

  up( &drbd_conf[minor].send_mutex );

  return err;
}

int drbd_ll_blocksize(int minor)
{
  int size = 0;
  kdev_t ll_dev = drbd_conf[minor].lo_file->f_dentry->d_inode->i_rdev;

  if (blksize_size[MAJOR(ll_dev)])
    size = blksize_size[MAJOR(ll_dev)][MINOR(ll_dev)];
  else 
    printk( KERN_ERR DEVICE_NAME ": LL device has no block size ?!?\n\n");

  if(size == 0) size = BLOCK_SIZE;

  printk( KERN_ERR DEVICE_NAME ": my ll_dev block size=%d/m=%d\n",size,minor);

  return size;  
}

/* these defines should go into blkdev.h 
   (if it will be ever includet into linus'es linux) */
#define RQ_DRBD_NOTHING	  0xf100
#define RQ_DRBD_SENT	  0xf200
#define RQ_DRBD_WRITTEN   0xf300
#define RQ_DRBD_SEC_WRITE 0xf400
#define RQ_DRBD_SOMETHING 0xf500

void drbd_end_req(struct request *req,int nextstate,int uptodate,
		  struct Drbd_Conf* mdev)
{
#if DBG
  switch(nextstate)
    {
    case RQ_DRBD_SENT:
      printk("S");  break;
    case RQ_DRBD_WRITTEN:
      printk("W");  break;
    case RQ_DRBD_SEC_WRITE: 
      printk("2");  break;
    case RQ_DRBD_NOTHING:
      printk("N");  break;
    }
#endif

  if(req->cmd == READ) goto end_it;
  switch( req->rq_status & 0xfffe )
    {
    case RQ_DRBD_SEC_WRITE:
      goto end_it;
    case RQ_DRBD_NOTHING:
      req->rq_status = nextstate | (uptodate ? 1 : 0) ; 
      break;
    case RQ_DRBD_SENT:
      if(nextstate == RQ_DRBD_WRITTEN) goto end_it;
      printk( KERN_ERR DEVICE_NAME": request state error(1)\n");
      break;
    case RQ_DRBD_WRITTEN:
      if(nextstate == RQ_DRBD_SENT) goto end_it;
      printk( KERN_ERR DEVICE_NAME": request state error(2)\n");
      break;
    default:
      printk( KERN_ERR DEVICE_NAME": request state error(3)\n");
    }
  return;

/* We only report uptodate == TRUE it both operations (WRITE && SEND)
   reported uptodate == TRUE 
*/

 end_it:
  if(!end_that_request_first(req, uptodate && (req->rq_status&1), DEVICE_NAME))
    end_that_request_last(req);  
}

void drbd_dio_end(struct buffer_head *bh, int uptodate)
{
  struct request *req = bh->b_dev_id;

  drbd_end_req(req,RQ_DRBD_WRITTEN,uptodate,
	       ((struct Drbd_buffer_head*)bh)->mdev);

  kfree(bh); /* bh is actually a Drbd_buffer_head */
}

/*
  We should _nerver_ sleep with the io_request_lock aquired. (See ll_rw_block)
  Up to now I have considered these ways out:
  * 1) unlock the io_request_lock for the time of the send 
         Not possible, because I do not have the flags for the unlock.
           -> Forget the flags, look at the loop block device!!
  * 2) postpone the send to some point in time when the request lock
       is not hold. 
         Maybe using the tq_scheduler task queue, or an dedicated
         execution context (kernel thread).

         I am not sure if tq_schedule is a good idea, because we
         could send some process to sleep, which would not sleep
	 otherwise.
	   -> tq_schedule is a bad idea, sometimes sock_sendmsg
	      behaves *bad* ( return value does not indicate
	      an error, but ... )

  Non atomic things, that need to be done are:
  sock_sendmsg(), kmalloc(,GFP_KERNEL) and ll_rw_block().
*/

/*static*/ void drbd_do_request( void )
{
  int minor=0;
  struct request *req;
  int sending;

  minor = MINOR(CURRENT->rq_dev);


  if(blksize_size[MAJOR_NR][minor] != (1 << drbd_conf[minor].blk_size_b))
    {
      /* If someone called set_blocksize() from fs/buffer.c ... */
      int new_blksize;

      spin_unlock_irq(&io_request_lock);
      printk( KERN_ERR DEVICE_NAME ": Block size change detected!\n");

      new_blksize = blksize_size[MAJOR_NR][minor];
      set_blocksize(drbd_conf[minor].lo_device,new_blksize);
      drbd_conf[minor].blk_size_b = drbd_log2(new_blksize);
      
      if(drbd_conf[minor].state == Primary)
	if(drbd_send_param(minor,BlkSizeChanged)<0)
	  printk( KERN_ERR DEVICE_NAME ": drbd_send_param() failed!\n");

      spin_lock_irq(&io_request_lock);       	 
    }

  while ( TRUE )
    {
      /* INIT_REQUEST; */

	if (!CURRENT) {
	  /* send getAck Packet and wait for answer... */
	  	break; 
	} 
	if (MAJOR(CURRENT->rq_dev) != MAJOR_NR) 
		panic(DEVICE_NAME ": request list destroyed"); 
	if (CURRENT->bh) { 
		if (!buffer_locked(CURRENT->bh)) 
			panic(DEVICE_NAME ": block not locked"); 
	}
	req = CURRENT;
	  

	/*
	  {
	  static const char *strs[2] = 
	  {
	  "READ",
	  "WRITE"
	  };
	  
	  printk( KERN_ERR DEVICE_NAME ": do_request(cmd=%s,sec=%ld,"
	  "nr_sec=%ld,cnr_sec=%ld,buf=%p,min=%d)",
	  strs[req->cmd == READ ? 0 : 1],req->sector,
	  req->nr_sectors,
	  req->current_nr_sectors,
	  req->buffer,minor);
	  }
	*/

	spin_unlock_irq(&io_request_lock);

	sending = 0;

	if( req->cmd == WRITE && drbd_conf[minor].state == Primary &&
	     ( drbd_conf[minor].cstate == Connected || 
	        ( drbd_conf[minor].cstate == Syncing && 
	          req->sector > drbd_conf[minor].synced_to)))
	  sending = 1;

	/* Do disk - IO */
	{
	  struct buffer_head *bh;
	  struct Drbd_buffer_head *dbh;
	  dbh = kmalloc(sizeof(struct Drbd_buffer_head),GFP_KERNEL);
	  if(!dbh)
	    {
	      printk( KERN_ERR DEVICE_NAME ": coul'd not kmalloc()\n");
	      return;
	    }
	  dbh->mdev = &drbd_conf[minor];
	  bh = &dbh->bh;

	  memcpy(bh,req->bh,sizeof(struct buffer_head));

	  bh->b_dev        = drbd_conf[minor].lo_device;
	  bh->b_state      = (1<<BH_Req) | (1<<BH_Dirty);
	  bh->b_list       = BUF_LOCKED;
	  bh->b_dev_id     = req;
	  bh->b_end_io     = drbd_dio_end;	  

	  if(sending) 
	    req->rq_status = RQ_DRBD_NOTHING;
	  else if(req->cmd == WRITE && drbd_conf[minor].state == Secondary)
	    req->rq_status = RQ_DRBD_SEC_WRITE | 0x0001;
	  else
	    req->rq_status = RQ_DRBD_SOMETHING | 0x0001;

	  ll_rw_block(req->cmd,1,&bh);
	}

	/* Send it out to the network */
	if( sending )
	  {
	    if(drbd_send(minor,Data,
			 req->current_nr_sectors<<9,
			 req->sector,req->buffer)>0)
	      {
		drbd_conf[minor].send_cnt++;
	      }  
	    drbd_end_req(req,RQ_DRBD_SENT,1,&drbd_conf[minor]);
	  }

	spin_lock_irq(&io_request_lock);       	 
	CURRENT = CURRENT->next;	
    }
}


int drbd_fsync(struct file * file, struct dentry * dentry)
{
  int minor;
  int retval=0;

  /* retval=block_fsync(file,dentry); */

  minor=MINOR(dentry->d_inode->i_rdev);
  retval=fsync_dev(MKDEV(MAJOR_NR,minor));
  /* fsync_dev(drbd_conf[minor].lo_device); not needed :-) */

  printk( KERN_ERR DEVICE_NAME ": sync minor= %d \n",minor);

  /* send a sync request ... */

  /* wait for ACK packet ... */

  return retval;
}

/*static*/ int drbd_ioctl(struct inode *inode, struct file *file, 
		      unsigned int cmd, unsigned long arg)
{
  int err;
  int minor;
  struct file *filp;

  minor=MINOR(inode->i_rdev);

  switch(cmd)
    {
#if LINUX_VERSION_CODE > 0x20300
	case BLKROSET:
	case BLKROGET:
	case BLKFLSBUF:
	case BLKSSZGET:
	case BLKPG:
		return blk_ioctl(inode->i_rdev, cmd, arg);
#else
    RO_IOCTLS(inode->i_rdev,arg);
#endif

    case DRBD_IOCTL_GET_VERSION:
      if((err=put_user(MOD_VERSION, (int *)arg))) return err;
      break;

    case DRBD_IOCTL_SET_STATE:
      fsync_dev(MKDEV(MAJOR_NR,minor));
      drbd_conf[minor].state=(Drbd_State)arg;
      if(blk_size[MAJOR_NR][minor])
	/*	set_device_ro(MKDEV(MAJOR_NR,minor),
		drbd_conf[minor].state != Primary);      */
      printk( KERN_ERR DEVICE_NAME ": set_state(%d)\n",drbd_conf[minor].state);
      break;
      
    case DRBD_IOCTL_SET_CONFIG:
      printk( KERN_ERR DEVICE_NAME ": set_config()\n");
      if((err=copy_from_user(&drbd_conf[minor].conf,(void*)arg,
			sizeof(struct ioctl_drbd_config))))
	return err;

      filp = fget(drbd_conf[minor].conf.lower_device);
      if(!filp) return -EINVAL;
      inode = filp->f_dentry->d_inode;
      if(!S_ISBLK(inode->i_mode)) return -EINVAL;
      if((err = blkdev_open(inode, filp)))
	{      
	  printk( KERN_ERR DEVICE_NAME ": blkdev_open( %d:%d ,) returned %d\n",
		  MAJOR(inode->i_rdev),MINOR(inode->i_rdev),err );
	  return err;	  
	}

      fsync_dev(MKDEV(MAJOR_NR,minor));
      drbd_thread_stop(&drbd_conf[minor].syncer);
      drbd_thread_stop(&drbd_conf[minor].receiver);
      drbd_free_resources(minor);

      if(!drbd_conf[minor].transfer_log)
	{
	  drbd_conf[minor].transfer_log = 
	    kmalloc(sizeof(u64)*drbd_conf[minor].conf.tl_size,
		    GFP_KERNEL);
	  tl_init(&drbd_conf[minor]);
	}

      drbd_conf[minor].lo_device = inode->i_rdev;
      drbd_conf[minor].lo_file = filp;

      drbd_conf[minor].cstate = Unconnected;

      drbd_thread_start(&drbd_conf[minor].receiver);

      break;

    default:
      return -EINVAL;
    }
  return 0;
}


/*static*/ int drbd_open(struct inode *inode, struct file *file)
{
  int minor;

  minor=MINOR(inode->i_rdev);

  if( (file->f_mode & FMODE_WRITE) && drbd_conf[minor].state == Secondary )
    {
      return -EROFS;      
    }

  printk( KERN_ERR DEVICE_NAME ": open(inode=%p,file=%p)"
	  "current=%p,minor=%d\n",inode,file,current,minor);


  MOD_INC_USE_COUNT;

  return 0;
}

/*static*/ int drbd_close(struct inode *inode, struct file *file)
{
  /* do not use *file (May be NULL, in case of a unmount :-) */
  int minor;

  minor=MINOR(inode->i_rdev);

  printk( KERN_ERR DEVICE_NAME ": close(inode=%p,file=%p)"
	  "current=%p,minor=%d\n",inode,file,current,minor);

  MOD_DEC_USE_COUNT;

  return 0;
}

void drbd_thread_init(int minor,struct Drbd_thread* thi,int (*func)(void*))
{
  thi->pid = 0;
  /*  thi->sem
      thi->exit   look at drbd_thread_start
  */
  thi->function = func;
  thi->minor = minor;
}

#if LINUX_VERSION_CODE > 0x20300
int drbd_init (void) 
#else
__initfunc(int drbd_init( void ))
#endif
{
	
  int i;
#if LINUX_VERSION_CODE > 0x20300
	drbd_proc = create_proc_read_entry("drbd", 0, &proc_root,
							drbd_proc_get_info, NULL);
	if(!drbd_proc)
#else
  if(proc_register(&proc_root, &drbd_proc_dir))
#endif
    {
      printk(MODULE_NAME"unable to register proc file.\n");
      return -EIO;
    }

  if ( register_blkdev( MAJOR_NR, DEVICE_NAME, &drbd_fops ) )
    {
      printk( KERN_ERR DEVICE_NAME ": Unable to get major %d\n",
	      MAJOR_NR );
      return -EBUSY;
    }

  /* Initialize size arrays. */
  
  for (i = 0; i < MINOR_COUNT; i++) 
    {
      drbd_blocksizes[i] = BLOCK_SIZE;
      drbd_conf[i].blk_size_b = drbd_log2(BLOCK_SIZE);
      drbd_sizes[i]=0;
      set_device_ro(MKDEV(MAJOR_NR,i),FALSE/*TRUE*/);     
      drbd_conf[i].sock = 0;
      drbd_conf[i].lo_file = 0;	
      drbd_conf[i].transfer_log = 0;
      drbd_conf[i].state = Secondary;
      drbd_conf[i].cstate = Unconfigured;
      drbd_conf[i].send_cnt=0;
      drbd_conf[i].recv_cnt=0;
      drbd_conf[i].s_timeout_t.function = drbd_send_timeout;
      init_timer(&drbd_conf[i].s_timeout_t);
      drbd_conf[i].synced_to=0;
      init_MUTEX(&drbd_conf[i].send_mutex);
      drbd_thread_init(i,&drbd_conf[i].receiver,drbdd_init);
      drbd_thread_init(i,&drbd_conf[i].syncer,drbd_syncer);
      drbd_conf[i].tl_lock = SPIN_LOCK_UNLOCKED;
    }
   
  blk_dev[ MAJOR_NR ].request_fn = DEVICE_REQUEST;
  blksize_size[ MAJOR_NR ] = drbd_blocksizes;
  blk_size[ MAJOR_NR ] = drbd_sizes; /* Size in Kb */

  return 0;
}
#if LINUX_VERSION_CODE > 0x20300
int init_module() 
#else
__initfunc(int init_module())
#endif
{
  printk(MODULE_NAME"module initialised. Version: %d\n",MOD_VERSION);

  return drbd_init();

}

void cleanup_module()
{
  int i;

  for (i = 0; i < MINOR_COUNT; i++) 
    {  
      fsync_dev(MKDEV(MAJOR_NR,i));
      drbd_thread_stop(&drbd_conf[i].syncer);
      drbd_thread_stop(&drbd_conf[i].receiver);
      drbd_free_resources(i);

      if(drbd_conf[i].transfer_log)
	 {
	   kfree(drbd_conf[i].transfer_log);
	   drbd_conf[i].transfer_log=0;
	 }      
    }

  if ( unregister_blkdev( MAJOR_NR, DEVICE_NAME ) != 0 )
    printk(MODULE_NAME"unregister of device failed\n");

  blk_dev[ MAJOR_NR ].request_fn = NULL;
  blksize_size[ MAJOR_NR ] = NULL;
  blk_size[ MAJOR_NR ] = NULL;
#if LINUX_VERSION_CODE > 0x20300 
  if (drbd_proc)
    remove_proc_entry ("drbd", &proc_root);
#else
  proc_unregister(&proc_root, drbd_proc_dir.low_ino);
#endif
}


/************************* Receiving part */
#define min(a,b) ( (a) < (b) ? (a) : (b) )
#define max(a,b) ( (a) > (b) ? (a) : (b) )

int drbd_send_param(int minor,int cmd)
{
  Drbd_ParameterBlock param;
  int err;
  kdev_t ll_dev = drbd_conf[minor].lo_file->f_dentry->d_inode->i_rdev;

  if (blk_size[MAJOR(ll_dev)])
    {
      param.my_size = 
	cpu_to_be64(blk_size[MAJOR(ll_dev)][MINOR(ll_dev)]);
    }
  else 
    printk( KERN_ERR DEVICE_NAME ": LL device has no size ?!?\n\n");

  param.my_blksize = cpu_to_be32(drbd_ll_blocksize(minor));

  param.my_state = cpu_to_be32(drbd_conf[minor].state);
  
  err=drbd_send(minor,cmd,sizeof(Drbd_ParameterBlock),0,&param);
  if(err>0) drbd_conf[minor].send_cnt++;
  
  return err;
}

struct socket* drbd_accept(struct socket* sock)
{
  struct socket *newsock;
  int err=0;

  lock_kernel();

  err=sock->ops->listen(sock, 5);
  if(err) goto out;

  if (!(newsock = sock_alloc())) 
    goto out;

  newsock->type = sock->type;
#if LINUX_VERSION_CODE > 0x20300
  newsock->ops = sock->ops;
#else
  err = sock->ops->dup(newsock, sock);
#endif
  if (err < 0) 
    goto out_release;

  err = newsock->ops->accept(sock, newsock, 0);
  if (err < 0)
    goto out_release;

  unlock_kernel();
  return newsock;

 out_release:
  sock_release(newsock);
 out:
  unlock_kernel();
  printk( KERN_ERR DEVICE_NAME ": accept failed! %d\n",err);
  return 0;
}

int drbd_recv(struct socket *sock, void * ubuf, size_t size)
{
  mm_segment_t oldfs;

  struct iovec iov;
  struct msghdr msg;
  int err=0;

  msg.msg_control=NULL;
  msg.msg_controllen=0;
  msg.msg_iovlen=1;
  msg.msg_iov=&iov;
  iov.iov_len=size;
  iov.iov_base=ubuf;
  msg.msg_name=NULL;
  msg.msg_namelen=0;
  msg.msg_flags = 0;

  lock_kernel();
  oldfs = get_fs(); set_fs(KERNEL_DS);
  /* Check if this get_fs() / set_fs stuff is needed for a kernel_thread */

  err=sock_recvmsg(sock, &msg, size, MSG_WAITALL );

  set_fs(oldfs);
  unlock_kernel();
  if(err != size ) 
    printk( KERN_ERR DEVICE_NAME ": sock_recvmsg returned %d\n",err);

  return err;
}

int drbd_connect(int minor)
{
  int err;
  struct socket* sock;

  if(drbd_conf[minor].sock) 
    {
      printk( KERN_ERR DEVICE_NAME ": There is already a socket!! \n");
      return 0;
    }

  err = sock_create(AF_INET, SOCK_STREAM, 0, &sock);
  if(err) {
    printk( KERN_ERR DEVICE_NAME ": sock_creat(..)=%d\n", err);
  }

  lock_kernel();
  err = sock->ops->connect(sock, 
		    (struct sockaddr*)drbd_conf[minor].conf.other_addr,
		    drbd_conf[minor].conf.other_addr_len, 0);
  unlock_kernel();

  if(err) 
    {
      struct socket* sock2;
      sock_release(sock);
      printk( KERN_ERR DEVICE_NAME": Unable to connect to server (%d)\n", err);

      err = sock_create(AF_INET, SOCK_STREAM, 0, &sock);
      if(err) {
	printk( KERN_ERR DEVICE_NAME ": sock_creat(..)=%d\n", err);
      }
      lock_kernel();
      err = sock->ops->bind(sock, 
			    (struct sockaddr*)drbd_conf[minor].conf.my_addr, 
			    drbd_conf[minor].conf.my_addr_len); 
      unlock_kernel();
      if(err){
	printk( KERN_ERR DEVICE_NAME ": Unable to bind (%d)\n", err);
	sock_release(sock);
	drbd_conf[minor].cstate = Unconnected;
	return 0;
      }

      drbd_conf[minor].cstate = WFConnection;
      sock2 = sock;

      sock = drbd_accept(sock2);
      sock_release(sock2);
      if(!sock)
	{
	  drbd_conf[minor].cstate = Unconnected;
	  return 0;
	}
    }

  drbd_conf[minor].sock=sock;
  err=drbd_send_param(minor,ReportParams);

  printk( KERN_ERR DEVICE_NAME": drbd_send_param()=%d \n", err);
  drbd_conf[minor].cstate = WFReportParams;

  return 1;
}

void drbdd(int minor)
{
  Drbd_Packet packet_header;
  kdev_t ll_dev = drbd_conf[minor].lo_file->f_dentry->d_inode->i_rdev;
  struct socket* my_sock = drbd_conf[minor].sock;

  while(TRUE)
    {
      if( drbd_recv(my_sock, &packet_header, sizeof(Drbd_Packet)) <= 0) 
	break;
      drbd_conf[minor].recv_cnt++;

      if( be32_to_cpu(packet_header.magic) != DRBD_MAGIC )
	{
	  printk(KERN_ERR DEVICE_NAME ": magic?? m: %ld "
		 "c: %d "
		 "l: %d "
		 "b: %ld\n",
		 (long)be32_to_cpu(packet_header.magic),
		 (int)be16_to_cpu(packet_header.command),
		 (int)be16_to_cpu(packet_header.length),
		 (long)be64_to_cpu(packet_header.block_nr) );

	  continue; 
	}

      switch(be16_to_cpu(packet_header.command))
	{
	case Data: 
	  {
	    struct buffer_head * bh;
	    unsigned long block_nr;

	    /*
	    printk(KERN_ERR DEVICE_NAME ": recv Data "
		   "block_nr=%ld len=%d/m=%d bs_bits=%d\n",
		   be64_to_cpu(packet_header.block_nr),
		   (int)be16_to_cpu(packet_header.length),
		   minor,drbd_conf[minor].blk_size_b); 
	    */

	    block_nr = be64_to_cpu(packet_header.block_nr) >> 
	                        (drbd_conf[minor].blk_size_b - 9);

	    bh = getblk(MKDEV(MAJOR_NR,minor),block_nr,
			be16_to_cpu(packet_header.length));
	    if(!bh) 
	      {
		printk(KERN_ERR DEVICE_NAME ": getblk()=0/m=%d\n",minor); 
		goto out;
	      }

	    if( drbd_recv(my_sock,bh->b_data,
			  be16_to_cpu(packet_header.length)) <= 0 )
	      goto out;

	    mark_buffer_uptodate(bh, 1);
	    mark_buffer_dirty(bh, 0);

	    ll_rw_block(WRITE, 1, &bh);
	    /* The ll_rw_block() ensures the correct write order, 
	       which is of major importance for journaling FSs    */
	    brelse(bh);

	    /**** transfer log ...***/
	    tl_send_ack(minor, be64_to_cpu(packet_header.block_nr));


	    break;
	  }
	case Ack:  
	  {
#define ACK_SPACE 11
	    u64 space[ACK_SPACE];
	    int rr,i,len;

	    printk(KERN_ERR DEVICE_NAME ": recv Ack/m=%d\n",minor);
	    
	    len = be16_to_cpu(packet_header.length);
	    
	    while(len)
	      {
		rr = drbd_recv(my_sock, space, min(ACK_SPACE*sizeof(u64),len));
		if(rr <= 0) break;
		len -= rr;
		rr = rr/sizeof(u64);

		for(i=0;i<rr;i++)
		  tl_release(&drbd_conf[minor],space[i],i);
	      }
	    	    
	    break;
	  }
	case SyncNow: 
	  printk(KERN_ERR DEVICE_NAME ": recv SyncNow/m=%d\n",minor); 
	  break;
	case BlkSizeChanged: /* fall trough */
	case ReportParams: 
	  {
	    Drbd_ParameterBlock param;
	    int blksize;	    

	    printk(KERN_ERR DEVICE_NAME ": recv ReportParams/m=%d\n",minor); 

	    if( drbd_recv(my_sock, &param, sizeof(Drbd_ParameterBlock)) <= 0) 
	      break;
	    
	    if(be16_to_cpu(packet_header.command)==BlkSizeChanged)
	      {
		blksize = be32_to_cpu(param.my_blksize);
	      }
	    else
	      {

		if (blk_size[MAJOR(ll_dev)])
		  {
		    blk_size[MAJOR_NR][minor] =
		      min(blk_size[MAJOR(ll_dev)][MINOR(ll_dev)],
			  be64_to_cpu(param.my_size));
		    printk(KERN_ERR DEVICE_NAME ": reported size=%ld\n",
			   (long)be64_to_cpu(param.my_size)); 
		    /*		 set_device_ro(MKDEV(MAJOR_NR,minor),
				 drbd_conf[minor].state != Primary);      */
		  }
		else
		  {
		    blk_size[MAJOR_NR][minor] = 0;
		    printk( KERN_ERR DEVICE_NAME "LL Device has no size?!?\n");
		  }

		blksize = max(be32_to_cpu(param.my_blksize),
			      drbd_ll_blocksize(minor));
	      }

	    set_blocksize(MKDEV(MAJOR_NR,minor),blksize);
	    set_blocksize(drbd_conf[minor].lo_device,blksize);
	    drbd_conf[minor].blk_size_b = drbd_log2(blksize);

	    printk( KERN_ERR DEVICE_NAME ": agreed blksize=%d\n",blksize);

	    /* Do wee nedd to adjust device size to end on block 
	       boundary ?? I do not think so ! */

	    if(drbd_conf[minor].cstate == WFReportParams)
	      {
		if(drbd_conf[minor].state == Primary && 
		   !drbd_conf[minor].conf.skip_sync) 
		  {
		    drbd_conf[minor].cstate = Syncing;
		    drbd_thread_start(&drbd_conf[minor].syncer);
		  }
		else
		  drbd_conf[minor].cstate = Connected;
	      }

	    break;
	  }
	default:
	  printk(KERN_ERR DEVICE_NAME ": unknown packet type!/m=%d\n",minor);
	  goto out;
	}
    }

 out:  
  if(drbd_conf[minor].sock)
    {
      printk( KERN_ERR DEVICE_NAME ": sock_release()minor=%d\n",minor);
      sock_release(drbd_conf[minor].sock);
      drbd_conf[minor].sock=0;
    }
  drbd_conf[minor].cstate=Unconnected;
}

int drbdd_init(void *arg)
{
  struct Drbd_thread* thi = (struct Drbd_thread*)arg;
  int minor = thi->minor;

  lock_kernel();
  exit_mm(current);    /* give up UL-memory context */
  exit_files(current); /* give up open filedescriptors */
  current->session = 1;
  current->pgrp = 1;
  current->fs->umask = 0;

  sprintf(current->comm, "drbdd_%d",minor);

  down( &thi->sem ); /* wait until parent has written its
			rpid variable */

  printk(KERN_ERR DEVICE_NAME ": receiver living/m=%d\n",minor);

  while(TRUE)
    {
      if(!drbd_connect(minor)) break;
      if(thi->exit==1) break;
      drbdd(minor);
      if(thi->exit==1) break;
    }

  printk(KERN_ERR DEVICE_NAME ": receiver exiting/m=%d\n",minor);

  thi->pid=0;
  up( &thi->sem );
  return 0;
}

void drbd_free_resources(int minor)
{
  if(drbd_conf[minor].sock)
    {
      sock_release(drbd_conf[minor].sock);
      drbd_conf[minor].sock=0;
      printk( KERN_ERR DEVICE_NAME ": sock_release()minor=%d\n",minor);
    }

  if(drbd_conf[minor].lo_file)
    {
      blkdev_release(drbd_conf[minor].lo_file->f_dentry->d_inode);
      fput(drbd_conf[minor].lo_file);
      drbd_conf[minor].lo_file=0;
      drbd_conf[minor].lo_device=0;
    }

  drbd_conf[minor].cstate = Unconfigured;
}

void drbd_thread_start(struct Drbd_thread* thi)
{
  int pid;

  if(thi->pid==0)
    {
      init_MUTEX_LOCKED(&thi->sem);
      thi->exit = 0;

      pid = kernel_thread(thi->function, (void *)thi, 0);

      if(pid < 0) 
	{
	  printk(KERN_ERR DEVICE_NAME ": Couldn't start thread (%d)\n", pid);
	  return;
	}

      printk(KERN_ERR DEVICE_NAME ": pid = %d\n",pid);  
      thi->pid=pid;
      up(&thi->sem);
    }
}

void _drbd_thread_stop(struct Drbd_thread* thi,int restart)
{
  if(thi->pid)
    {
      int err;

      if(restart) thi->exit=2;
      else        thi->exit=1;      

      init_MUTEX_LOCKED(&thi->sem);
      err = kill_proc_info(SIGTERM,NULL,thi->pid);

      if(err==0)
	down( &thi->sem ); /* wait until the thread
					   has closed the socket */
      else
	printk( KERN_ERR DEVICE_NAME ": could not send signal\n");

      /* printk( KERN_ERR DEVICE_NAME ": (pseudo) waitpid returned \n"); */

      current->state = TASK_INTERRUPTIBLE;
      schedule_timeout(HZ/10); 

      /*
	This would be the *nice* solution, but it crashed
	my machine...
	
	struct task_struct *p;
	read_lock(&tasklist_lock);
	p = find_task_by_pid(drbd_conf[minor].rpid);
	p->p_pptr = current;
	errno = send_sig_info(SIGTERM, NULL, p);
	read_unlock(&tasklist_lock);
	interruptible_sleep_on(&current->wait_chldexit);
      */
    }
}

/* ********* the syncer ******** */

int drbd_syncer(void *arg)
{
  struct Drbd_thread* thi=(struct Drbd_thread*)arg;  
  int minor = thi->minor;
  int interval;
  int amount = 32; 
  /* FIXME: get the half of the size of the socket write buffer */
  int blocks;
  int blocksize;

  lock_kernel();
  exit_mm(current);    /* give up UL-memory context */
  exit_files(current); /* give up open filedescriptors */
  current->session = 1;
  current->pgrp = 1;
  current->fs->umask = 0;

  sprintf(current->comm, "drbd_syncer_%d",minor);

  down( &thi->sem ); /* wait until parent has written its
				     rpid variable */

  printk(KERN_ERR DEVICE_NAME ": syncer living/m=%d\n",minor);

  drbd_conf[minor].synced_to = ( blk_size[MAJOR_NR][minor] -
			      (blksize_size[MAJOR_NR][minor]>>10) ) <<1;  
 restart:
  blocksize = blksize_size[MAJOR_NR][minor];

  drbd_conf[minor].synced_to =   /* align synced_to to blocksize */
    (drbd_conf[minor].synced_to) & ~((blocksize>>9)-1);

  interval = amount * HZ / drbd_conf[minor].conf.sync_rate;
  blocks = (amount << 10) / blocksize;

  printk(KERN_ERR DEVICE_NAME ": synced_to=%ld "
	 "blks=%d "
	 "int=%d \n"
	 ,drbd_conf[minor].synced_to,blocks,interval);

  while(TRUE)
    {
      int i,rr;
      unsigned long block_nr,new_sector;
      struct buffer_head *bh;      

      current->state = TASK_INTERRUPTIBLE;
      schedule_timeout(interval);

      for(i=0;i<blocks;i++)
	{
	  if(thi->exit==1) goto out;
	  if(blocksize != blksize_size[MAJOR_NR][minor]) goto restart;

	  block_nr=drbd_conf[minor].synced_to>>(drbd_conf[minor].blk_size_b-9);

	  bh = getblk(MKDEV(MAJOR_NR,minor),block_nr,blocksize);

	  if(!buffer_uptodate(bh))
	    {
	      ll_rw_block(READ,1,&bh);
	      wait_on_buffer(bh);
	      if(!buffer_uptodate(bh)) 
		{
		  brelse(bh);
		  goto out;
		}
	    }

	  rr=drbd_send(minor,Data,blocksize,drbd_conf[minor].synced_to,
		       bh->b_data);

	  brelse(bh);

	  if(rr > 0)
	    {
	      drbd_conf[minor].send_cnt++;
	    }
	  else
	    {
	      printk(KERN_ERR DEVICE_NAME ": syncer send failed!!\n");
	      goto out;
	    }


	  /*
	  printk(KERN_ERR DEVICE_NAME ": syncer send: "
		 "block_nr=%ld len=%d\n",
		 block_nr,
		 blocksize);
	  */

	  new_sector = drbd_conf[minor].synced_to - (blocksize>>9);
	  if(new_sector > drbd_conf[minor].synced_to) goto done;
	  drbd_conf[minor].synced_to = new_sector;
	}
    }
 done:
  drbd_conf[minor].cstate = Connected;

 out:
  drbd_conf[minor].synced_to=0;
  printk(KERN_ERR DEVICE_NAME ": syncer exiting/m=%d\n",minor);
  thi->pid=0;
  up( &thi->sem );
  return 0;
}

