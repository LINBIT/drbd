@ kmalloc_flex_rule @
expression ptr;
identifier fam;
expression count;
expression GFP;
@@
- kmalloc_flex(*ptr, fam, count, GFP)
+ kmalloc(sizeof(*ptr) + sizeof(*ptr->fam) * count, GFP)

@ kzalloc_flex_rule @
expression ptr;
identifier fam;
expression count;
expression GFP;
@@
- kzalloc_flex(*ptr, fam, count, GFP)
+ kzalloc(sizeof(*ptr) + sizeof(*ptr->fam) * count, GFP)
