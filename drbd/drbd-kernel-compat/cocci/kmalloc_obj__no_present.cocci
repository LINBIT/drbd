@ kmalloc_type @
type T;
expression GFP;
@@
- kmalloc_obj(T, GFP)
+ kmalloc(sizeof(T), GFP)

@ kmalloc_expr @
expression E;
expression GFP;
@@
- kmalloc_obj(E, GFP)
+ kmalloc(sizeof(E), GFP)

@ kzalloc_type @
type T;
expression GFP;
@@
- kzalloc_obj(T, GFP)
+ kzalloc(sizeof(T), GFP)

@ kzalloc_expr @
expression E;
expression GFP;
@@
- kzalloc_obj(E, GFP)
+ kzalloc(sizeof(E), GFP)

@ kzalloc_flex_rule @
expression ptr;
identifier fam;
expression count;
expression GFP;
@@
- kzalloc_flex(*ptr, fam, count, GFP)
+ kzalloc(struct_size(ptr, fam, count), GFP)
