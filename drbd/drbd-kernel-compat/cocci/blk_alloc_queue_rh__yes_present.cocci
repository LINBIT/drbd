@ blk_alloc_queue @
identifier make_request_fn;
@@
- blk_alloc_queue(make_request_fn, NUMA_NO_NODE)
+ blk_alloc_queue_rh(make_request_fn, NUMA_NO_NODE)

