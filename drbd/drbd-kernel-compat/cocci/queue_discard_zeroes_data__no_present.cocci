@@
expression q;
@@
(
- !queue_discard_zeroes_data(q)
+ 1 /* !queue_discard_zeroes_data(q) */
|
- queue_discard_zeroes_data(q)
+ 0 /* queue_discard_zeroes_data(q) */
)
