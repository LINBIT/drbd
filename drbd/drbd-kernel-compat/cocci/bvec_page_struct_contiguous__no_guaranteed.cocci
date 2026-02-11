// On kernels before v5.2, bio_add_page() may merge physically contiguous
// pages without guaranteeing that their struct page objects are contiguous.
// Use nth_page() for safe page iteration instead of pointer arithmetic.
@@
expression page, order;
@@
 drbd_peer_req_strip_bio(...)
 {
 <...
-		page += 1 << order;
+		page = nth_page(page, 1 << order);
 ...>
 }
