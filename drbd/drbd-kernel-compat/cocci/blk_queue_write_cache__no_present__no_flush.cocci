@@
@@
// Older kernels either flag affected bios with BIO_RW_BARRIER, or do not know
// how to handle this at all. No need to "announce" driver support.
-blk_queue_write_cache(...);
