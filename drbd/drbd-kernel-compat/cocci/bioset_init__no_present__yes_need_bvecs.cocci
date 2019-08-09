@@
identifier find_struct_bio_set.bs;
expression re, size, front_pad, flags;
statement S;
@@
- re = bioset_init(&bs, size, front_pad, flags);
+ bs = bioset_create(size, front_pad, flags);
...
- if (re)
+ if (bs == NULL)
	S
