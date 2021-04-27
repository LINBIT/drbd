@@
expression part;
@@
// part_stat_read{,_accum} changed from taking a "struct hd_struct *" to a
// "struct block_device". Since this is a macro, and the "part" member on
// struct gendisk was not renamed but only changed its type, we miraculously
// only have to add a "&".
part_stat_read_accum(
- part
+ &part
, ...
 )
