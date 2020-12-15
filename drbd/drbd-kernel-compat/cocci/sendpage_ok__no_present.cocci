@@
struct page *p;
@@
(
- !sendpage_ok(p)
+ (PageSlab(page) || page_count(page) < 1)
|
- sendpage_ok(p)
+ (!PageSlab(page) && page_count(page) >= 1)
)
