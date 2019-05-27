@@
identifier find_struct_bio_set.bs;
expression re, size, front_pad;
statement S;
@@
- re = bioset_init(&bs, size, front_pad, ...);
+ bs = bioset_create(size, front_pad, 0);
...
- if (re)
+ if (bs == NULL)
	S
