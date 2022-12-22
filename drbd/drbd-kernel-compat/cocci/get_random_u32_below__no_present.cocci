@@
expression i;
@@
- get_random_u32_below(i)
+ (prandom_u32() % i)
