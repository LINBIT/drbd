@@
struct ratelimit_state *r;
int i, b;
@@
- ratelimit_state_init(r, i, b);
+ rs->interval = i;
+ rs->burst = b;
+ rs->printed = 0;
+ rs->missed = 0;
+ rs->begin = 0;
