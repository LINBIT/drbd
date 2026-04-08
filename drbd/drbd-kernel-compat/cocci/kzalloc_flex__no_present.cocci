@ kmalloc_flex_rule @
expression ptr;
identifier fam;
expression count;
expression GFP;
@@
- kmalloc_flex(*ptr, fam, count, GFP)
+ kmalloc(struct_size(ptr, fam, count), GFP)

@ kzalloc_flex_rule @
expression ptr;
identifier fam;
expression count;
expression GFP;
@@
- kzalloc_flex(*ptr, fam, count, GFP)
+ kzalloc(struct_size(ptr, fam, count), GFP)
