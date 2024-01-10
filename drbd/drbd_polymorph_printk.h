/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DRBD_POLYMORPH_PRINTK_H
#define DRBD_POLYMORPH_PRINTK_H

#if !defined(CONFIG_DYNAMIC_DEBUG)
#undef DEFINE_DYNAMIC_DEBUG_METADATA
#undef __dynamic_pr_debug
#undef DYNAMIC_DEBUG_BRANCH
#define DEFINE_DYNAMIC_DEBUG_METADATA(D, F) const char *D = F; ((void)D)
#define __dynamic_pr_debug(D, F, args...) do { (void)(D); if (0) printk(F, ## args); } while (0)
#define DYNAMIC_DEBUG_BRANCH(D) false
#endif

#define __drbd_printk(level, fmt, args...)				\
	printk(level fmt, ## args)
#define __drbd_dyn_dbg(descriptor, fmt, args...)			\
	__dynamic_pr_debug(descriptor, fmt, ## args)

#define ___drbd_printk_device(prmacro, rlt, device, lvl_or_desc, fmt, args...)\
({									\
	const struct drbd_device *__d =					\
		(const struct drbd_device *)(device);			\
	const struct drbd_resource *__r = __d->resource;		\
	const char *__unregistered = "";				\
	if (test_bit(UNREGISTERED, &__d->flags))			\
		__unregistered = "/unregistered/";			\
	if (drbd_device_ratelimit(__d, rlt))				\
		prmacro(lvl_or_desc, "drbd %s%s/%u drbd%u: " fmt,	\
			__unregistered, __r->name, __d->vnr, __d->minor,\
			## args);					\
})

#define ___drbd_printk_resource(prmacro, rlt, resource, lvl_or_desc, fmt, args...)\
({									\
	const struct drbd_resource *__r =				\
		(const struct drbd_resource *)(resource);		\
	const char *__unregistered = "";				\
	if (test_bit(R_UNREGISTERED, &__r->flags))			\
		__unregistered = "/unregistered/";			\
	if (drbd_resource_ratelimit(__r, rlt))				\
		prmacro(lvl_or_desc, "drbd %s%s: " fmt,			\
			__unregistered, __r->name, ## args);		\
})

// As long as the connection is still "registered", the resource
// can not yet be "unregistered", no need to test R_UNREGISTERED
#define ___drbd_printk_peer_device(prmacro, rlt, peer_device, lvl_or_desc, fmt, args...)\
({									\
	const struct drbd_peer_device *__pd;				\
	const struct drbd_device *__d;					\
	const struct drbd_connection *__c;				\
	const struct drbd_resource *__r;				\
	const char *__cn;						\
	const char *__unregistered = "";				\
	rcu_read_lock();						\
	__pd = (const struct drbd_peer_device *)(peer_device);		\
	__d = __pd->device;						\
	__c = __pd->connection;						\
	__r = __d->resource;						\
	__cn = rcu_dereference(__c->transport.net_conf)->name;		\
	if (test_bit(C_UNREGISTERED, &__c->flags))			\
		__unregistered = "/unregistered/";			\
	if (drbd_peer_device_ratelimit(__pd, rlt))			\
		prmacro(lvl_or_desc, "drbd %s%s/%u drbd%u %s: " fmt,		\
			__unregistered, __r->name, __d->vnr, __d->minor, __cn,	\
			 ## args);					\
	rcu_read_unlock();						\
})

#define ___drbd_printk_connection(prmacro, rlt, connection, lvl_or_desc, fmt, args...)	\
({									\
	const struct drbd_connection *__c =				\
		(const struct drbd_connection *)(connection);		\
	const struct drbd_resource *__r = __c->resource;		\
	const char *__cn;						\
	const char *__unregistered = "";				\
	rcu_read_lock();						\
	__cn = rcu_dereference(__c->transport.net_conf)->name;		\
	if (test_bit(C_UNREGISTERED, &__c->flags))			\
		__unregistered = "/unregistered/";			\
	if (drbd_connection_ratelimit(__c, rlt))			\
		prmacro(lvl_or_desc, "drbd %s%s %s: " fmt,		\
			__unregistered, __r->name, __cn, ## args);	\
	rcu_read_unlock();						\
})

#define __drbd_printk_device(rlt, device, level, fmt, args...)\
	___drbd_printk_device(__drbd_printk, rlt, device, level, fmt, ## args)
#define __drbd_printk_resource(rlt, resource, level, fmt, args...)\
	 ___drbd_printk_resource(__drbd_printk, rlt, resource, level, fmt, ## args)
#define __drbd_printk_peer_device(rlt, peer_device, level, fmt, args...)\
	 ___drbd_printk_peer_device(__drbd_printk, rlt, peer_device, level, fmt, ## args)
#define __drbd_printk_connection(rlt, connection, level, fmt, args...)\
	 ___drbd_printk_connection(__drbd_printk, rlt, connection, level, fmt, ## args)

void drbd_printk_with_wrong_object_type(void);
void drbd_dyn_dbg_with_wrong_object_type(void);

#define __drbd_printk_choose_cond(obj, struct_name) \
	(__builtin_types_compatible_p(typeof(obj), struct drbd_ ## struct_name *) || \
	 __builtin_types_compatible_p(typeof(obj), const struct drbd_ ## struct_name *))

#define __drbd_obj_ratelimit(struct_name, obj, rlt)		\
	({							\
	int __rlt = (rlt);					\
	BUILD_BUG_ON(!__drbd_printk_choose_cond(obj, struct_name)); \
	BUILD_BUG_ON(__rlt < -1);				\
	BUILD_BUG_ON(__rlt >= (int)ARRAY_SIZE(obj->ratelimit)); \
	__rlt == -1 ? 1						\
	: __ratelimit(/* unconst cast ratelimit state */	\
		(struct ratelimit_state *)(unsigned long)	\
		&obj->ratelimit[__rlt]);			\
	})

#define drbd_device_ratelimit(obj, rlt)		\
	__drbd_obj_ratelimit(device, obj, D_RL_D_ ## rlt)
#define drbd_resource_ratelimit(obj, rlt)	\
	__drbd_obj_ratelimit(resource, obj, D_RL_R_ ## rlt)
#define drbd_connection_ratelimit(obj, rlt)	\
	__drbd_obj_ratelimit(connection, obj, D_RL_C_ ## rlt)
#define drbd_peer_device_ratelimit(obj, rlt)	\
	__drbd_obj_ratelimit(peer_device, obj, D_RL_PD_ ## rlt)

#define drbd_printk(ratelimit_type, level, obj, fmt, args...) \
	__builtin_choose_expr(__drbd_printk_choose_cond(obj, device), \
	__drbd_printk_device(ratelimit_type, obj, level, fmt, ## args), \
	\
	__builtin_choose_expr(__drbd_printk_choose_cond(obj, resource), \
	__drbd_printk_resource(ratelimit_type, obj, level, fmt, ## args), \
	\
	__builtin_choose_expr(__drbd_printk_choose_cond(obj, connection), \
	__drbd_printk_connection(ratelimit_type, obj, level, fmt, ## args), \
	\
	__builtin_choose_expr(__drbd_printk_choose_cond(obj, peer_device), \
	__drbd_printk_peer_device(ratelimit_type, obj, level, fmt, ## args), \
	\
	drbd_printk_with_wrong_object_type() \
	))))

#define __drbd_dyn_dbg_if_same_type(obj, struct_name, fmt, args...) \
({ \
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt);		\
	if (DYNAMIC_DEBUG_BRANCH(descriptor)) {			\
		___drbd_printk_ ## struct_name(			\
			__drbd_dyn_dbg,				\
				NOLIMIT, obj,			\
				&descriptor, fmt, ## args);	\
	}							\
})

#define dynamic_drbd_dbg(obj, fmt, args...) \
	__builtin_choose_expr(__drbd_printk_choose_cond(obj, device), \
	__drbd_dyn_dbg_if_same_type(obj, device, fmt, ## args), \
	\
	__builtin_choose_expr(__drbd_printk_choose_cond(obj, resource), \
	__drbd_dyn_dbg_if_same_type(obj, resource, fmt, ## args), \
	\
	__builtin_choose_expr(__drbd_printk_choose_cond(obj, connection), \
	__drbd_dyn_dbg_if_same_type(obj, connection, fmt, ## args), \
	\
	__builtin_choose_expr(__drbd_printk_choose_cond(obj, peer_device), \
	__drbd_dyn_dbg_if_same_type(obj, peer_device, fmt, ## args), \
	\
	drbd_dyn_dbg_with_wrong_object_type() \
	))))

#define drbd_emerg_ratelimit(obj, fmt, args...) \
	drbd_printk(GENERIC, KERN_EMERG, obj, fmt, ## args)
#define drbd_alert_ratelimit(obj, fmt, args...) \
	drbd_printk(GENERIC, KERN_ALERT, obj, fmt, ## args)
#define drbd_crit_ratelimit(obj, fmt, args...) \
	drbd_printk(GENERIC, KERN_CRIT, obj, fmt, ## args)
#define drbd_err_ratelimit(obj, fmt, args...) \
	drbd_printk(GENERIC, KERN_ERR, obj, fmt, ## args)
#define drbd_warn_ratelimit(obj, fmt, args...) \
	drbd_printk(GENERIC, KERN_WARNING, obj, fmt, ## args)
#define drbd_notice_ratelimit(obj, fmt, args...) \
	drbd_printk(GENERIC, KERN_NOTICE, obj, fmt, ## args)
#define drbd_info_ratelimit(obj, fmt, args...) \
	drbd_printk(GENERIC, KERN_INFO, obj, fmt, ## args)

#define drbd_emerg(obj, fmt, args...) \
	drbd_printk(NOLIMIT, KERN_EMERG, obj, fmt,  ## args)
#define drbd_alert(obj, fmt, args...) \
	drbd_printk(NOLIMIT, KERN_ALERT, obj, fmt,  ## args)
#define drbd_crit(obj, fmt, args...) \
	drbd_printk(NOLIMIT, KERN_CRIT, obj, fmt,  ## args)
#define drbd_err(obj, fmt, args...) \
	drbd_printk(NOLIMIT, KERN_ERR, obj, fmt,  ## args)
#define drbd_warn(obj, fmt, args...) \
	drbd_printk(NOLIMIT, KERN_WARNING, obj, fmt,  ## args)
#define drbd_notice(obj, fmt, args...) \
	drbd_printk(NOLIMIT, KERN_NOTICE, obj, fmt,  ## args)
#define drbd_info(obj, fmt, args...) \
	drbd_printk(NOLIMIT, KERN_INFO, obj, fmt,  ## args)

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
#define expect(x, exp) ({					\
		bool _bool = (exp);				\
		if (!_bool)					\
			drbd_err_ratelimit(x,			\
				"ASSERTION %s FAILED in %s\n",	\
				#exp, __func__);		\
		_bool;						\
		})

#endif
