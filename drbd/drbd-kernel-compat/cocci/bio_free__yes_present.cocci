@@
@@
+ static void ___bio_destructor_drbd(struct bio *bio)
+ {
+	bio_free(bio, drbd_md_io_bio_set);
+ }

bio_alloc_drbd(...)
{
+	struct bio *___bio;
...
-	return
+	___bio =
 bio_alloc_bioset(...);
+	if (!___bio)
+		return NULL;
+	___bio->bi_destructor = ___bio_destructor_drbd;
+	return ___bio;
}
