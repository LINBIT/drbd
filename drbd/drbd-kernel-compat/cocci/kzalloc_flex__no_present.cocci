@ kzalloc_flex_rule @
expression ptr;
identifier fam;
expression count;
expression GFP;
@@
- kzalloc_flex(*ptr, fam, count, GFP)
+ kzalloc(struct_size(ptr, fam, count), GFP)
