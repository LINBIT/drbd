#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/spinlock.h>
#include <linux/module.h>
#include <net/ipv6.h>
#include <drbd_personality.h>
#include <drbd_int.h>

static LIST_HEAD(personality_classes);
static DECLARE_RWSEM(personality_classes_lock);

static struct drbd_personality_class *__find_personality_class(const char *personality_name)
{
	struct drbd_personality_class *personality_class;

	list_for_each_entry(personality_class, &personality_classes, list)
		if (!strcmp(personality_class->name, personality_name))
			return personality_class;

	return NULL;
}

int drbd_register_personality_class(struct drbd_personality_class *personality_class, int version,
				  int drbd_personality_size)
{
	int rv = 0;
	if (version != DRBD_PERSONALITY_API_VERSION) {
		pr_err("DRBD_PERSONALITY_API_VERSION not compatible\n");
		return -EINVAL;
	}

	if (drbd_personality_size != sizeof(struct drbd_personality)) {
		pr_err("sizeof(drbd_personality) not compatible\n");
		return -EINVAL;
	}

	down_write(&personality_classes_lock);
	if (__find_personality_class(personality_class->name)) {
		pr_err("personality class '%s' already registered\n", personality_class->name);
		rv = -EEXIST;
	} else
		list_add_tail(&personality_class->list, &personality_classes);
	up_write(&personality_classes_lock);
	return rv;
}

void drbd_unregister_personality_class(struct drbd_personality_class *personality_class)
{
	down_write(&personality_classes_lock);
	if (!__find_personality_class(personality_class->name)) {
		pr_crit("unregistering unknown personality class '%s'\n",
			personality_class->name);
		BUG();
	}
	list_del_init(&personality_class->list);
	up_write(&personality_classes_lock);
}

static struct drbd_personality_class *get_personality_class(const char *name)
{
	struct drbd_personality_class *pc;

	down_read(&personality_classes_lock);
	pc = __find_personality_class(name);
	if (pc && !try_module_get(pc->module))
		pc = NULL;
	up_read(&personality_classes_lock);
	return pc;
}

struct drbd_personality_class *drbd_get_personality_class(const char *name)
{
	struct drbd_personality_class *pc = get_personality_class(name);

	if (!pc) {
		request_module("drbd_personality_%s", name);
		pc = get_personality_class(name);
	}

	return pc;
}

void drbd_put_personality_class(struct drbd_personality_class *pc)
{
	/* convenient in the error cleanup path */
	if (!pc)
		return;
	down_read(&personality_classes_lock);
	module_put(pc->module);
	up_read(&personality_classes_lock);
}

void drbd_print_personalitys_loaded(struct seq_file *seq)
{
	struct drbd_personality_class *pc;

	down_read(&personality_classes_lock);

	seq_puts(seq, "Personalities (api:" __stringify(DRBD_PERSONALITY_API_VERSION) "):");
	list_for_each_entry(pc, &personality_classes, list) {
		seq_printf(seq, " %s (%s)", pc->name,
				pc->module->version ? pc->module->version : "NONE");
	}
	seq_putc(seq, '\n');

	up_read(&personality_classes_lock);
}

/* Personality abstractions */
EXPORT_SYMBOL_GPL(drbd_register_personality_class);
EXPORT_SYMBOL_GPL(drbd_unregister_personality_class);
