#include <linux/kobject.h>
#include <linux/slab.h>

/* These functions mimmic the post 2.6.24 kobject api on the pre 2.6.24 api
 */

static void dynamic_kobj_release(struct kobject *kobj)
{
	pr_debug("kobject: (%p): %s\n", kobj, __func__);
	kfree(kobj);
}

static struct kobj_type dynamic_kobj_ktype = {
	.release	= dynamic_kobj_release,
	.sysfs_ops	= NULL,
};

static struct kobject *kobject_create(void)
{
	struct kobject *kobj;

	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	if (!kobj)
		return NULL;

	kobject_init(kobj);
	kobj->ktype = &dynamic_kobj_ktype;
	return kobj;
}

struct kobject *kobject_create_and_add(const char *name, struct kobject *parent)
{
	struct kobject *kobj;
	int retval;

	kobj = kobject_create();
	if (!kobj)
		return NULL;

	kobject_set_name(kobj, "%s", name);
	kobj->parent = parent;
	retval = kobject_add(kobj);
	if (retval) {
		printk(KERN_WARNING "%s: kobject_add error: %d\n",
		       __func__, retval);
		kobject_put(kobj);
		kobj = NULL;
	}
	return kobj;
}

int kobject_init_and_add(struct kobject *kobj, struct kobj_type *ktype,
				struct kobject *parent, const char *name)
{
	int retval;

	kobject_init(kobj);
	kobj->ktype = ktype;
	kobject_set_name(kobj, "%s", name);
	kobj->parent = parent;

	retval = kobject_add(kobj);
	if (retval) {
		printk(KERN_WARNING "%s: kobject_add error: %d\n",
		       __func__, retval);
		kobject_put(kobj);
	}
	return retval;
}
