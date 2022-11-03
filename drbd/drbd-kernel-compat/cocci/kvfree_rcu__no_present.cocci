@@
expression ptr;
@@
- kvfree_rcu(ptr);
+ synchronize_rcu();
+ kfree(ptr);
