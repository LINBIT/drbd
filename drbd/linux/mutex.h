/* "Backport" of the mutex to older Linux-2.6.x kernels.
 */
#ifndef __LINUX_MUTEX_H
#define __LINUX_MUTEX_H

#include <asm/semaphore.h>

struct mutex {
	struct semaphore sem;
};

static inline void mutex_init(struct mutex *m)
{
	sema_init(&m->sem, 0);
}

static inline void mutex_lock(struct mutex *m)
{
	down(&m->sem);
}

static inline void mutex_unlock(struct mutex *m)
{
	up(&m->sem);
}

#endif
