@@ expression R, V; @@
(
- refcount_inc(R)
+ atomic_inc(R)
|
- refcount_read(R)
+ atomic_read(R)
|
- refcount_dec_and_test(R)
+ atomic_dec_and_test(R)
|
- refcount_set(R, V)
+ atomic_set(R, V)
)
