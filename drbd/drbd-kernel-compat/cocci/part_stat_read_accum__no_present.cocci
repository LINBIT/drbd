@@
expression part;
identifier sectors;
@@
- (int)part_stat_read_accum(part, sectors)
+ (int)part_stat_read(part, sectors[0]) + (int)part_stat_read(part, sectors[1])
