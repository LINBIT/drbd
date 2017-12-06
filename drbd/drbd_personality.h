#ifndef DRBD_PERSONALITY_H
#define DRBD_PERSONALITY_H

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/socket.h>

/* Whenever touch this file in a non-trivial way, increase the
   DRBD_PERSONALITY_API_VERSION
   So that transport compiled against an older version of this
   header will no longer load in a module that assumes a newer
   version. */
#define DRBD_PERSONALITY_API_VERSION 1

#if 0
#define tr_printk(level, transport, fmt, args...)  ({		\
	rcu_read_lock();					\
	printk(level "drbd %s %s:%s: " fmt,			\
	       (transport)->log_prefix,				\
	       (transport)->class->name,			\
	       rcu_dereference((transport)->net_conf)->name,	\
	       ## args);					\
	rcu_read_unlock();					\
	})

#define tr_err(transport, fmt, args...) \
	tr_printk(KERN_ERR, transport, fmt, ## args)
#define tr_warn(transport, fmt, args...) \
	tr_printk(KERN_WARNING, transport, fmt, ## args)
#define tr_info(transport, fmt, args...) \
	tr_printk(KERN_INFO, transport, fmt, ## args)

#define TR_ASSERT(x, exp)							\
	do {									\
		if (!(exp))							\
			tr_err(x, "ASSERTION %s FAILED in %s\n", 		\
				 #exp, __func__);				\
	} while (0)
#endif

struct drbd_request;

/* Each personality implementation should embed a struct drbd_personality
   into it's instance data structure. */
struct drbd_personality {
	struct drbd_personality_ops *ops;
	struct drbd_personality_class *class;

	/* TODO(rck): rethink the log_prefix, copy&paste from transport */
	const char *log_prefix;		/* resource name */

	int n, k;
	size_t block_size;
};

struct drbd_personality_stats {

};

struct drbd_personality_ops {
	int (*encode)(struct drbd_personality *, struct drbd_request *req, u64 in_bm);
	int (*decode)(struct drbd_personality *, struct drbd_request *req, u64 in_bm);
	/*
	int (*reshape)(struct drbd_personality *);
	*/

	void (*stats)(struct drbd_personality *, struct drbd_personality_stats *stats);
};

struct drbd_personality_class {
	const char *name;
	const int instance_size;
	struct module *module;
	int (*init)(struct drbd_personality *);
	struct list_head list;
};

/* drbd_personality.c */
extern int drbd_register_personality_class(struct drbd_personality_class *personality_class,
					 int api_version,
					 int drbd_personality_size);
extern void drbd_unregister_personality_class(struct drbd_personality_class *personality_class);
extern struct drbd_personality_class *drbd_get_personality_class(const char *personality_name);
extern void drbd_put_personality_class(struct drbd_personality_class *);
extern void drbd_print_personalitys_loaded(struct seq_file *seq);

#endif
