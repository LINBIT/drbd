@@
typedef blk_qc_t;
@@
- void
+ blk_qc_t
drbd_submit_bio(...)
{
	...
- 	return;
+	return BLK_QC_T_NONE;
}
