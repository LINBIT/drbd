@@
expression F, qu;
fresh identifier flags = "____flags";
@@
- blk_queue_flag_set(F, qu);
+ {
+ unsigned long flags;
+ spin_lock_irqsave(qu->queue_lock, flags);
+ queue_flag_set(F, qu);
+ spin_unlock_irqrestore(qu->queue_lock, flags);
+ }

@@
expression F, qu;
fresh identifier flags = "____flags";
@@
- blk_queue_flag_clear(F, qu);
+ {
+ unsigned long flags;
+ spin_lock_irqsave(qu->queue_lock, flags);
+ queue_flag_clear(F, qu);
+ spin_unlock_irqrestore(qu->queue_lock, flags);
+ }
