@@
expression p;
fresh identifier r = "____rv";
@@
// this is very specific to drbd's use of this function,
// it is *not* a general purpose solution.
- sched_set_fifo_low(p);
+ struct sched_param param = { .sched_priority = 2 };
+ int r;
+ r = sched_setscheduler(p, SCHED_RR, &param);
+ if (r < 0)
+ 	drbd_err(connection, "drbd_ack_receiver: ERROR set priority, ret=%d\n", r);
