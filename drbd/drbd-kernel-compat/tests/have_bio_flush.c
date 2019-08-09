/* {"version": "2.6.32-504", "comment": "RHEL6 backported REQ_FLUSH as BIO_FLUSH; there is no corresponding upstream commit for this change"} */
#include <linux/blk_types.h>

enum bio_rw_flags dummy = BIO_FLUSH;
