// It turned out that Ubuntu bionic kernel's IO performance drops
// to about 10% when it gets driven with 1MiB BIOs. On that kernel
// let the resync go up to 512 KiB per BIO only.
@@
identifier device;
@@
static int make_resync_request(...)
{
...
-queue_max_hw_sectors(device->rq_queue) >> (BM_BLOCK_SHIFT - SECTOR_SHIFT)
+queue_max_hw_sectors(device->rq_queue) >> (BM_BLOCK_SHIFT - SECTOR_SHIFT + 1)
...
}
