@@
expression page;
expression offset;
identifier address;
@@
// kunmap takes a kmapped page, while kunmap_local takes any address within the page.
// patch it back so that kunmap gets passed the page.
address = 
(
- kmap_local_page(page)
+ kmap(page)
|
- kmap_local_page(page) + offset
+ kmap(page) + offset
)
...
- kunmap_local(address)
+ kunmap(page)
