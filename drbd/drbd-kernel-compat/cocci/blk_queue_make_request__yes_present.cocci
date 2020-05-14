@ rm_blk_alloc_queue @
identifier make_request_fn;
@@
- blk_alloc_queue(make_request_fn, NUMA_NO_NODE)
+ blk_alloc_queue(GFP_KERNEL)

@@
identifier rm_blk_alloc_queue.make_request_fn;
@@
drbd_create_device(...)
{
	...
+	blk_queue_make_request(q, make_request_fn);
	blk_queue_write_cache(...);
	...
}
