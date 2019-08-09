@ find_make_request_void @
struct request_queue *q;
identifier fn;
@@
 blk_queue_make_request(q, fn)

@@ identifier find_make_request_void.fn; @@
- blk_qc_t
+ void
fn(...);

@@
identifier find_make_request_void.fn;
expression ret;
@@
- blk_qc_t
+ void
fn(...)
{
...
// just drop original return code
- return ret;
+ return;
}

@@
@@
- BLK_QC_T_NONE
+ 0
