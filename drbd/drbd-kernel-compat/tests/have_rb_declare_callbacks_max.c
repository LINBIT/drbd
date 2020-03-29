#include <linux/rbtree_augmented.h>

struct s {
	struct rb_node rb;
	int x;
};

int f(struct s*);

RB_DECLARE_CALLBACKS_MAX(static, a, struct s, rb, int, x, f);
