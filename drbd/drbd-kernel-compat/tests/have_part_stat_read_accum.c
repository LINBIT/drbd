/* { "version": "v4.18-rc5", "commit": "59767fbd49d794b4499d30b314df6c0d4aca584b", "comment": "part_stat_read_accum was added to read all STAT_* field entries", "author": "Michael Callahan <michaelcallahan@fb.com>", "date": "Wed Jul 18 04:47:37 2018 -0700" } */

#include <linux/part_stat.h>

#ifndef part_stat_read_accum
# error "Not defined"
#endif
