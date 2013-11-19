#ifndef KREF_DEBUG_H
#define KREF_DEBUG_H

#include <linux/seq_file.h>

#ifdef CONFIG_KREF_DEBUG

#define KREF_DEBUG_HOLDER_MAX 16

extern struct list_head kref_debug_objects;
extern spinlock_t kref_debug_lock;

struct kref_debug_class {
	const char *name;
	const char *holder_name[KREF_DEBUG_HOLDER_MAX];
};

struct kref_debug_info {
	const struct kref_debug_class *class;
	struct kref *kref;
	int holders[KREF_DEBUG_HOLDER_MAX];
	struct list_head objects;
};

void initialize_kref_debugging(void);
void kref_debug_init(struct kref_debug_info *debug_info,
		     struct kref *kref,
		     const struct kref_debug_class *class);
void kref_debug_destroy(struct kref_debug_info *debug_info);
void kref_debug_get(struct kref_debug_info *debug_info, int holder_nr);
void kref_debug_sub(struct kref_debug_info *debug_info, int refs, int holder_nr);
void print_kref_debug_info(struct seq_file *seq);
static inline void kref_debug_put(struct kref_debug_info *debug_info, int holder_nr)
{
	kref_debug_sub(debug_info, 1, holder_nr);
}
#else
struct kref_debug_class {};
struct kref_debug_info {};
static inline void initialize_kref_debugging(void)
{}
#define kref_debug_init(D, K, C) __kref_debug_init(D, K)
static inline void __kref_debug_init(struct kref_debug_info *debug_info, struct kref *kref)
{}
static inline void kref_debug_destroy(struct kref_debug_info *debug_info)
{}
static inline void kref_debug_get(struct kref_debug_info *debug_info, int holder_nr)
{}
static inline void kref_debug_sub(struct kref_debug_info *debug_info, int refs, int holder_nr)
{}
static inline void kref_debug_put(struct kref_debug_info *debug_info, int holder_nr)
{}
static inline void print_kref_debug_info(struct seq_file *seq)
{}
#endif

#endif
