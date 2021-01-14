@@
identifier q, enabled, fua;
symbol true, false;
@@
// enumerate all possible combinations of the "enabled" and "fua" parameters,
// so that the resulting code looks neater,
// but fall back to a generic version just in case.
(
- blk_queue_write_cache(q, false, false)
+ blk_queue_flush(q, 0)
|
- blk_queue_write_cache(q, false, true)
+ blk_queue_flush(q, REQ_FUA)
|
- blk_queue_write_cache(q, true, false)
+ blk_queue_flush(q, REQ_FLUSH)
|
- blk_queue_write_cache(q, true, true)
+ blk_queue_flush(q, REQ_FLUSH | REQ_FUA)
|
- blk_queue_write_cache(q, enabled, fua)
+ blk_queue_flush(q, (enabled ? REQ_FLUSH : 0) | (fua ? REQ_FUA : 0))
);
