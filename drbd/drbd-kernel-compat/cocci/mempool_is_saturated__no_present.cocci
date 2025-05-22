@@
typedef mempool_t;
typedef bool;
@@
enum rcv_timeou_kind { ... };
+ #include <linux/mempool.h>
+ static inline bool mempool_is_saturated(mempool_t *pool)
+ {
+ 	return READ_ONCE(pool->curr_nr) >= pool->min_nr;
+ }
