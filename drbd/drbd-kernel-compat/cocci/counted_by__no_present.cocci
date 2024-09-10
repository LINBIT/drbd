@@
type T;
identifier s, x;
attribute name __counted_by;
@@
struct s {
...
	T x
-	__counted_by(...)
	;
...
};
