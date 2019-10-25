// RHEL 6.1 ("not quite 2.6.32") backported FLUSH/FUA as BIO_RW_FLUSH/FUA {{{2
// and at that time also introduced the defines BIO_FLUSH/FUA.
// There is also REQ_FLUSH/FUA, but these do NOT share the same value space
// as the bio rw flags, yet.
// This applies to at least up to RHEL 6.6.
@@
@@
(
- REQ_PREFLUSH
+ (1UL << BIO_RW_FLUSH)
|
- REQ_FUA
+ (1UL << BIO_RW_FUA)
|
- REQ_HARDBARRIER
+ (1UL << BIO_RW_BARRIER)
|
- REQ_DISCARD
+ (1UL << BIO_RW_DISCARD)
|
- REQ_SYNC
+ (1UL << BIO_RW_SYNCIO)
|
- REQ_NOIDLE
+ (1UL << BIO_RW_NOIDLE)
|
- REQ_META
+ (1UL << BIO_RW_META)
|
- REQ_UNPLUG
+ (1UL << BIO_RW_UNPLUG)
|
- REQ_RAHEAD
+ (1UL << BIO_RW_AHEAD)
)
