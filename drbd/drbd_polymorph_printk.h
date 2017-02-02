#ifndef DRBD_POLYMORPH_PRINTK_H
#define DRBD_POLYMORPH_PRINTK_H

#define __drbd_printk_device(level, device, fmt, args...)		\
	({								\
		const struct drbd_device *__d = (device);		\
		const struct drbd_resource *__r = __d->resource;	\
		printk(level "drbd %s/%u drbd%u: " fmt,			\
			__r->name, __d->vnr, __d->minor, ## args);	\
	})

#define __drbd_printk_peer_device(level, peer_device, fmt, args...)	\
	({								\
		const struct drbd_device *__d;				\
		const struct drbd_connection *__c;			\
		const struct drbd_resource *__r;			\
		const char *__cn;					\
		rcu_read_lock();					\
		__d = (peer_device)->device;				\
		__c = (peer_device)->connection;			\
		__r = __d->resource;					\
		__cn = rcu_dereference(__c->transport.net_conf)->name;	\
		printk(level "drbd %s/%u drbd%u %s: " fmt,		\
			__r->name, __d->vnr, __d->minor, __cn, ## args);\
		rcu_read_unlock();					\
	})

#define __drbd_printk_resource(level, resource, fmt, args...) \
	printk(level "drbd %s: " fmt, (resource)->name, ## args)

#define __drbd_printk_connection(level, connection, fmt, args...) \
	({	rcu_read_lock(); \
		printk(level "drbd %s %s: " fmt, (connection)->resource->name,  \
		       rcu_dereference((connection)->transport.net_conf)->name, ## args); \
		rcu_read_unlock(); \
	})

void drbd_printk_with_wrong_object_type(void);

#define __drbd_printk_if_same_type(obj, type, func, level, fmt, args...) \
	(__builtin_types_compatible_p(typeof(obj), type) || \
	 __builtin_types_compatible_p(typeof(obj), const type)), \
	func(level, (const type)(obj), fmt, ## args)

#define drbd_printk(level, obj, fmt, args...) \
	__builtin_choose_expr( \
	  __drbd_printk_if_same_type(obj, struct drbd_device *, \
			     __drbd_printk_device, level, fmt, ## args), \
	  __builtin_choose_expr( \
	    __drbd_printk_if_same_type(obj, struct drbd_resource *, \
			       __drbd_printk_resource, level, fmt, ## args), \
	    __builtin_choose_expr( \
	      __drbd_printk_if_same_type(obj, struct drbd_connection *, \
				 __drbd_printk_connection, level, fmt, ## args), \
	      __builtin_choose_expr( \
		__drbd_printk_if_same_type(obj, struct drbd_peer_device *, \
				 __drbd_printk_peer_device, level, fmt, ## args), \
	        drbd_printk_with_wrong_object_type()))))

#if defined(disk_to_dev)
#define drbd_dbg(device, fmt, args...) \
	dev_dbg(disk_to_dev(device->vdisk), fmt, ## args)
#elif defined(DEBUG)
#define drbd_dbg(device, fmt, args...) \
	drbd_printk(KERN_DEBUG, device, fmt, ## args)
#else
#define drbd_dbg(device, fmt, args...) \
	do { if (0) drbd_printk(KERN_DEBUG, device, fmt, ## args); } while (0)
#endif

#if defined(dynamic_dev_dbg) && defined(disk_to_dev)
#define dynamic_drbd_dbg(device, fmt, args...) \
	dynamic_dev_dbg(disk_to_dev(device->vdisk), fmt, ## args)
#else
#define dynamic_drbd_dbg(device, fmt, args...) \
	drbd_dbg(device, fmt, ## args)
#endif

#define drbd_emerg(device, fmt, args...) \
	drbd_printk(KERN_EMERG, device, fmt, ## args)
#define drbd_alert(device, fmt, args...) \
	drbd_printk(KERN_ALERT, device, fmt, ## args)
#define drbd_err(device, fmt, args...) \
	drbd_printk(KERN_ERR, device, fmt, ## args)
#define drbd_warn(device, fmt, args...) \
	drbd_printk(KERN_WARNING, device, fmt, ## args)
#define drbd_info(device, fmt, args...) \
	drbd_printk(KERN_INFO, device, fmt, ## args)

#if defined(DEBUG)
#define drbd_debug(obj, fmt, args...) \
	drbd_printk(KERN_DEBUG, obj, fmt, ## args)
#else
#define drbd_debug(obj, fmt, args...)
#endif


#define drbd_ratelimit() \
({						\
	static DEFINE_RATELIMIT_STATE(_rs,	\
		DEFAULT_RATELIMIT_INTERVAL,	\
		DEFAULT_RATELIMIT_BURST);	\
	__ratelimit(&_rs);			\
})

#define D_ASSERT(x, exp)							\
	do {									\
		if (!(exp))							\
			drbd_err(x, "ASSERTION %s FAILED in %s\n",		\
				 #exp, __func__);				\
	} while (0)

/**
 * expect  -  Make an assertion
 *
 * Unlike the assert macro, this macro returns a boolean result.
 */
#define expect(x, exp) ({							\
		bool _bool = (exp);						\
		if (!_bool && drbd_ratelimit())					\
			drbd_err(x, "ASSERTION %s FAILED in %s\n",		\
			        #exp, __func__);				\
		_bool;								\
		})

#endif
