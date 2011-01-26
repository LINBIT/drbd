#include <linux/rbtree.h>

/* introduced with commit b945d6b2, Linux 2.6.35-rc5 */

void foo(void) {
	struct rb_node *n;

	rb_augment_insert((struct rb_node *) NULL,
			  (rb_augment_f) NULL,
			  NULL);

	n = rb_augment_erase_begin((struct rb_node *)NULL);
	rb_augment_erase_end((struct rb_node *) NULL, (rb_augment_f) NULL, NULL);
}
