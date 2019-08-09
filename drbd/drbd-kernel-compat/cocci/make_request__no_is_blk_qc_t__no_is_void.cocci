@ find_make_request_int @
struct request_queue *q;
identifier fn;
@@
 blk_queue_make_request(q, fn)

@@ identifier find_make_request_int.fn; @@
- blk_qc_t
+ int
fn(...);

@@
identifier find_make_request_int.fn;
identifier ret;
@@
- blk_qc_t
+ int
fn(...)
{
...
// just drop original return code
- return ret;
+ return 0;
}

@@
@@
- BLK_QC_T_NONE
+ 0
