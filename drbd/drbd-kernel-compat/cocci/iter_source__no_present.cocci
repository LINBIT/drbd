// The iov_iter direction initializers ITER_SOURCE / ITER_DEST were added in
// v6.2 by commit de4eda9de2d9 ("use less confusing names for iov_iter
// direction initializers"). Before that, the raw WRITE / READ values were
// used. Provide them for files that still reference ITER_SOURCE (e.g. the TLS
// copy path in dtt_send_page()).

@@
@@
- ITER_SOURCE
+ WRITE

@@
@@
- ITER_DEST
+ READ
