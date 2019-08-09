@ find_blk_status_t @
typedef blk_status_t, u8;
@@
- blk_status_t
+ u8

@@ expression s; @@
- blk_status_to_errno(s)
+ (s == BLK_STS_OK ? 0 : s == BLK_STS_RESOURCE ? -ENOMEM : s == BLK_STS_NOTSUPP ? -EOPNOTSUPP : -EIO)

@@ expression e; @@
- errno_to_blk_status(e)
+ (e == 0 ? BLK_STS_OK : e == -ENOMEM ? BLK_STS_RESOURCE : e == -EOPNOTSUPP ? BLK_STS_NOTSUPP : BLK_STS_IOERR)

@@ @@
(
- BLK_STS_OK
+ 0
|
- BLK_STS_NOTSUPP
+ 1
|
- BLK_STS_MEDIUM
+ 7
|
- BLK_STS_RESOURCE
+ 9
|
- BLK_STS_IOERR
+ 10
)
