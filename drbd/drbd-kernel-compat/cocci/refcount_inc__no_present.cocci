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
|
- refcount_sub_and_test(V, R)
+ atomic_sub_and_test(V, R)
|
- refcount_inc_not_zero(R)
+ atomic_inc_not_zero(R)
)

@@ typedef refcount_t, atomic_t; @@
- refcount_t
+ atomic_t
