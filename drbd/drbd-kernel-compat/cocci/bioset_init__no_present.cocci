@find_mempool_t@
typedef mempool_t;
identifier mp;
@@
- mempool_t
+ mempool_t *
mp;

@find_struct_bio_set@
identifier bs;
@@
- struct bio_set
+ struct bio_set *
bs;

@@
identifier find_struct_bio_set.bs;
expression GFP, n;
@@
(
bio_alloc_bioset(GFP, n,
- &bs
+ bs
 )
|
- bioset_initialized(&bs)
+ (bs != NULL)
)

@@
identifier find_struct_bio_set.bs;
@@
- bioset_exit(&bs);
+ if (bs) { bioset_free(bs); bs = NULL; }

@@
identifier find_mempool_t.mp;
expression min_nr, order, mem_cache, V, F;
@@
(
- mempool_exit(&mp);
+ if (mp) { mempool_destroy(mp); mp = NULL; }
|
- mempool_init_page_pool(&mp, min_nr, order)
+ ((mp = mempool_create_page_pool(min_nr, order)) == NULL ? -ENOMEM : 0)
|
- mempool_init_slab_pool(&mp, min_nr, mem_cache)
+ ((mp = mempool_create_slab_pool(min_nr, mem_cache)) == NULL ? -ENOMEM : 0)
|
mempool_free(V,
- &mp
+ mp
 )
|
mempool_alloc(
- &mp
+ mp
, F)
)
