@@
type T;
@@
- kmalloc_obj(T)
+ kmalloc_obj(T, GFP_KERNEL)

@@
expression E;
@@
- kmalloc_obj(E)
+ kmalloc_obj(E, GFP_KERNEL)

@@
type T;
@@
- kzalloc_obj(T)
+ kzalloc_obj(T, GFP_KERNEL)

@@
expression E;
@@
- kzalloc_obj(E)
+ kzalloc_obj(E, GFP_KERNEL)
