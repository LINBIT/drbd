@@
expression e;
@@
- bvec_virt(&e)
+ (page_address(e.bv_page) + e.bv_offset)
