#include <linux/spinlock.h>
#include <linux/seq_file.h>
#include <linux/kref.h>
#include "kref_debug.h"

struct list_head kref_debug_objects;
spinlock_t kref_debug_lock;

void initialize_kref_debugging(void)
{
	INIT_LIST_HEAD(&kref_debug_objects);
	spin_lock_init(&kref_debug_lock);
}

void kref_debug_init(struct kref_debug_info *debug_info,
		     struct kref *kref,
		     const struct kref_debug_class *class)
{
	unsigned long irq_flags;
	int i;

	debug_info->class = class;
	debug_info->kref = kref;
	debug_info->lost = false;
	for (i = 0; i < KREF_DEBUG_HOLDER_MAX ; i++)
		debug_info->holders[i] = 0;
	spin_lock_irqsave(&kref_debug_lock, irq_flags);
	list_add(&debug_info->objects, &kref_debug_objects);
	spin_unlock_irqrestore(&kref_debug_lock, irq_flags);
}

static int number_of_debug_refs(struct kref_debug_info *debug_info)
{
	int i, refs = 0;

	for (i = 0; i < KREF_DEBUG_HOLDER_MAX; i++)
		refs += debug_info->holders[i];

	return refs;
}

static bool has_refs(struct kref_debug_info *debug_info)
{
	return number_of_debug_refs(debug_info) != -1;
}

void __check_kref_debug_info(struct kref_debug_info *debug_info,
			     const char *file, int line)
{
	int debug_refs, refs;

	if (debug_info->lost)
		return;

	debug_refs = number_of_debug_refs(debug_info);
	refs = atomic_read(&debug_info->kref->refcount);

	if (debug_refs + 1 != refs) {
		printk(KERN_ERR "KREF TRACKING LOST (c = %s, r = %d, dr = %d)\n",
		       debug_info->class->name, refs, debug_refs);

		if (file)
			printk(KERN_ERR "POSITION %s:%d\n", file, line);

		dump_stack();

		debug_info->lost = true;
	}
}

static void check_debug_info_consistency(struct kref_debug_info *debug_info)
{
	__check_kref_debug_info(debug_info, NULL, 0);
}

void kref_debug_destroy(struct kref_debug_info *debug_info)
{
	unsigned long irq_flags;
	int i;

	spin_lock_irqsave(&kref_debug_lock, irq_flags);
	__check_kref_debug_info(debug_info, NULL, 0);
	check_debug_info_consistency(debug_info);
	if (has_refs(debug_info)) {
		printk(KERN_ERR "ASSERT FAILED\n");
		printk(KERN_ERR "object of class: %s\n", debug_info->class->name);
		for (i = 0; i < KREF_DEBUG_HOLDER_MAX; i++) {
			if (debug_info->holders[i] == 0)
				continue;
			printk(KERN_ERR "  [%d] = %d (%s)\n", i, debug_info->holders[i],
			       debug_info->class->holder_name[i] ?: "");
		}
		printk(KERN_ERR "\n");
	}

	list_del(&debug_info->objects);
	spin_unlock_irqrestore(&kref_debug_lock, irq_flags);
}

void kref_debug_get(struct kref_debug_info *debug_info, int holder_nr)
{
	unsigned long irq_flags;

	if (holder_nr >= KREF_DEBUG_HOLDER_MAX) {
		printk(KERN_ERR "Increase KREF_DEBUG_HOLDER_MAX\n");
		return;
	}

	spin_lock_irqsave(&kref_debug_lock, irq_flags);
	debug_info->holders[holder_nr]++;
	check_debug_info_consistency(debug_info);
	spin_unlock_irqrestore(&kref_debug_lock, irq_flags);
}

void kref_debug_sub(struct kref_debug_info *debug_info, int refs, int holder_nr)
{
	unsigned long irq_flags;

	if (holder_nr >= KREF_DEBUG_HOLDER_MAX) {
		printk(KERN_ERR "Increase KREF_DEBUG_HOLDER_MAX\n");
		return;
	}

	spin_lock_irqsave(&kref_debug_lock, irq_flags);
	check_debug_info_consistency(debug_info);
	debug_info->holders[holder_nr] -= refs;
	spin_unlock_irqrestore(&kref_debug_lock, irq_flags);
}

void print_kref_debug_info(struct seq_file *seq)
{
	struct kref_debug_info *debug_info;
	int i;

	spin_lock_irq(&kref_debug_lock);
	list_for_each_entry(debug_info, &kref_debug_objects, objects) {
		int debug_refs, refs;

		debug_refs = number_of_debug_refs(debug_info);
		refs = atomic_read(&debug_info->kref->refcount);

		seq_printf(seq, "object of class: %s (r = %d, dr = %d)\n",
			   debug_info->class->name, refs, debug_refs);
		for (i = 0; i < KREF_DEBUG_HOLDER_MAX; i++) {
			if (debug_info->holders[i] == 0)
				continue;
			seq_printf(seq, "  [%d] = %d", i, debug_info->holders[i]);
			if (debug_info->class->holder_name[i])
				seq_printf(seq, " (%s)", debug_info->class->holder_name[i]);
			seq_printf(seq, "\n");
		}
		seq_printf(seq, "\n");
	}
	spin_unlock_irq(&kref_debug_lock);
}

