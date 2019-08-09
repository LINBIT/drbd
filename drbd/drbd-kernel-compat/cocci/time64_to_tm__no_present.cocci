@@
expression totalsecs;
int offset;
struct tm *result;
typedef time_t;
@@
- time64_to_tm(totalsecs, offset, result)
+ time_to_tm((time_t) totalsecs, offset, result)
