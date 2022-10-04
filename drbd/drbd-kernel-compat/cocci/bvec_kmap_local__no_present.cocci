@@
identifier ptr, bvec;
@@
recv_dless_read(...)
{
<...
ptr =
- bvec_kmap_local(&bvec)
+ kmap(bvec.bv_page) + bvec.bv_offset
...
- kunmap_local(ptr);
+ kunmap(bvec.bv_page);
...>
}

// As of this writing (Linux 5.19), I am actually pretty sure that this special
// case is not required on "modern" kernel, i.e. the kmap_atomic is not
// necessary here. It was introduced with 3d0e63754fa4 ("drbd: Convert from
// ahash to shash"), but we don't seem to be in a context where the _atomic is
// required. More likely, this was just copied from the scatter-gather code that
// was there before, to make the aforementioned commit not change any behavior.
//
// However, I cannot guarantee that this is always the case on all the kernels
// we support. So just introduce a special case instead of having to debug an
// obscure bug on an ancient kernel later.
@@
identifier ptr, bvec;
@@
drbd_csum_bio(...)
{
<...
ptr =
- bvec_kmap_local(&bvec)
+ kmap_atomic(bvec.bv_page) + bvec.bv_offset
...
- kunmap_local(ptr);
+ kunmap_atomic(ptr);
...>
}
