@@
identifier r;
@@
- r->start_jif = bio_start_io_acct(r->master_bio);
+ r->start_jif = start_jif;
+ generic_start_io_acct(r->device->rq_queue, bio_data_dir(r->master_bio),
+ 			r->i.size >> 9, &r->device->vdisk->part0);

@@
identifier r;
@@
- bio_end_io_acct(r->master_bio, r->start_jif);
+ generic_end_io_acct(r->device->rq_queue, bio_data_dir(r->master_bio),
+		      &r->device->vdisk->part0, r->start_jif);
