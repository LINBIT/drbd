#ifndef DRBD_POLYMORPH_PRINTK_H
#define DRBD_POLYMORPH_PRINTK_H

#if !defined(CONFIG_DYNAMIC_DEBUG)
#define DEFINE_DYNAMIC_DEBUG_METADATA(D, F) const char *D = F
#define __dynamic_pr_debug(D, F, args...) do { (void)(D); if (0) printk(F, ## args); } while(0)
#define DYNAMIC_DEBUG_BRANCH(D) false
#endif


#define __drbd_printk_drbd_device_prep(device) \
	const struct drbd_device *__d = (device);		\
	const struct drbd_resource *__r = __d->resource;
#define __drbd_printk_drbd_device_fmt(fmt)	"drbd %s/%u drbd%u: " fmt
#define __drbd_printk_drbd_device_args()	__r->name, __d->vnr, __d->minor
#define __drbd_printk_drbd_device_unprep()


#define __drbd_printk_drbd_peer_device_prep(peer_device)		\
	const struct drbd_device *__d;				\
	const struct drbd_connection *__c;			\
	const struct drbd_resource *__r;			\
	const char *__cn;					\
	rcu_read_lock();					\
	__d = (peer_device)->device;				\
	__c = (peer_device)->connection;			\
	__r = __d->resource;					\
	__cn = rcu_dereference(__c->transport.net_conf)->name;
#define __drbd_printk_drbd_peer_device_fmt(fmt) \
	"drbd %s/%u drbd%u %s: " fmt
#define __drbd_printk_drbd_peer_device_args() \
	__r->name, __d->vnr, __d->minor, __cn
#define __drbd_printk_drbd_peer_device_unprep() \
	rcu_read_unlock();

#define __drbd_printk_drbd_resource_prep(resource) \
	const struct drbd_resource *__r = resource;
#define __drbd_printk_drbd_resource_fmt(fmt) "drbd %s: " fmt
#define __drbd_printk_drbd_resource_args()	__r->name
#define __drbd_printk_drbd_resource_unprep(resource)

#define __drbd_printk_drbd_connection_prep(connection)		\
	const struct drbd_connection *__c = (connection);	\
	const struct drbd_resource *__r = __c->resource;	\
	const char *__cn;					\
	rcu_read_lock();					\
	__cn = rcu_dereference(__c->transport.net_conf)->name;
#define __drbd_printk_drbd_connection_fmt(fmt)			\
	"drbd %s %s: " fmt
#define __drbd_printk_drbd_connection_args()			\
	__r->name, __cn
#define __drbd_printk_drbd_connection_unprep()			\
	rcu_read_unlock();					\

void drbd_printk_with_wrong_object_type(void);
void drbd_dyn_dbg_with_wrong_object_type(void);

#define __drbd_printk_choose_cond(obj, struct_name) \
	(__builtin_types_compatible_p(typeof(obj), struct struct_name *) || \
	 __builtin_types_compatible_p(typeof(obj), const struct struct_name *))
#define __drbd_printk_if_same_type(obj, struct_name, level, fmt, args...) \
	__drbd_printk_choose_cond(obj, struct_name), \
({ \
	__drbd_printk_ ## struct_name ## _prep((const struct struct_name *)(obj)) \
	printk(level __drbd_printk_ ## struct_name ## _fmt(fmt), \
		__drbd_printk_ ## struct_name ## _args(), ## args); \
	__drbd_printk_ ## struct_name ## _unprep() \
})

#define drbd_printk(level, obj, fmt, args...) \
	__builtin_choose_expr( \
	  __drbd_printk_if_same_type(obj, drbd_device, level, fmt, ## args), \
	  __builtin_choose_expr( \
	    __drbd_printk_if_same_type(obj, drbd_resource, level, fmt, ## args), \
	    __builtin_choose_expr( \
	      __drbd_printk_if_same_type(obj, drbd_connection, level, fmt, ## args), \
	      __builtin_choose_expr( \
		__drbd_printk_if_same_type(obj, drbd_peer_device, level, fmt, ## args), \
	        drbd_printk_with_wrong_object_type()))))

#if defined(DEBUG)
#define drbd_dbg(device, fmt, args...) \
	drbd_printk(KERN_DEBUG, device, fmt, ## args)
#else
#define drbd_dbg(device, fmt, args...) \
	do { if (0) drbd_printk(KERN_DEBUG, device, fmt, ## args); } while (0)
#endif

#define __drbd_dyn_dbg_if_same_type(obj, struct_name, fmt, args...) \
	__drbd_printk_choose_cond(obj, struct_name), \
({ \
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt);		\
	if (DYNAMIC_DEBUG_BRANCH(descriptor)) {			\
		__drbd_printk_ ## struct_name ## _prep((const struct struct_name *)(obj)) \
		__dynamic_pr_debug(&descriptor, __drbd_printk_ ## struct_name ## _fmt(fmt), \
			__drbd_printk_ ## struct_name ## _args(), ## args); \
		__drbd_printk_ ## struct_name ## _unprep()	\
	}							\
})

#define dynamic_drbd_dbg(obj, fmt, args...) \
	__builtin_choose_expr( \
	  __drbd_dyn_dbg_if_same_type(obj, drbd_device, fmt, ## args), \
	  __builtin_choose_expr( \
	    __drbd_dyn_dbg_if_same_type(obj, drbd_resource, fmt, ## args), \
	    __builtin_choose_expr( \
	      __drbd_dyn_dbg_if_same_type(obj, drbd_connection, fmt, ## args), \
	      __builtin_choose_expr( \
		__drbd_dyn_dbg_if_same_type(obj, drbd_peer_device, fmt, ## args), \
	        drbd_dyn_dbg_with_wrong_object_type()))))

#define drbd_emerg(device, fmt, args...) \
	drbd_printk(KERN_EMERG, device, fmt, ## args)
#define drbd_alert(device, fmt, args...) \
	drbd_printk(KERN_ALERT, device, fmt, ## args)
#define drbd_crit(device, fmt, args...) \
	drbd_printk(KERN_CRIT, device, fmt, ## args)
#define drbd_err(device, fmt, args...) \
	drbd_printk(KERN_ERR, device, fmt, ## args)
#define drbd_warn(device, fmt, args...) \
	drbd_printk(KERN_WARNING, device, fmt, ## args)
#define drbd_notice(device, fmt, args...) \
	drbd_printk(KERN_NOTICE, device, fmt, ## args)
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
