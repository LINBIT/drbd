@@
identifier object, member, callback;
@@
- tasklet_setup(&object->member, callback)
+ tasklet_init(&object->member, callback, (unsigned long)object)

@@
identifier tasklet_fn, t, object_struct, object, tasklet;
@@
void
-tasklet_fn(struct tasklet_struct *t)
+tasklet_fn(unsigned long data)
{
- struct object_struct *object = from_tasklet(object, t, tasklet);
+ struct object_struct *object = (struct object_struct *) data;
  ...
}
