@@
expression DST;
expression SRC;
@@
- strscpy(DST, SRC)
+ strscpy(DST, SRC, sizeof(DST))
