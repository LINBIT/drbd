@@
identifier d;
expression ql;
expression node;
identifier err;
@@
d = blk_alloc_disk(
-	ql,
	node);
if (
-	IS_ERR(d)
+	!d
 ) {
-	err = PTR_ERR(d);
	...
}
