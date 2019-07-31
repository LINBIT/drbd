@@
identifier q, bio;
@@
drbd_make_request(struct request_queue *q, struct bio *bio)
{
+ struct bio_list *current_bio_list;
...
blk_queue_split(...);
+ current_bio_list = current->bio_list;
+ current->bio_list = NULL;
...
__drbd_make_request(...);
+ current->bio_list = current_bio_list;
return ...;
}
