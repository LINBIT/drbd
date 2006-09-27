#ifndef DRBD_TAG_MAGIC_H
#define DRBD_TAG_MAGIC_H

#define TT_END     0
#define TT_REMOVED 0xE000

// declare packet_type enums
enum packet_types {
#define PACKET(name, number, fields) P_ ## name = number,
#define INTEGER(pn,pr,member)
#define INT64(pn,pr,member)
#define BIT(pn,pr,member)
#define STRING(pn,pr,member,len)
#include "drbd_nl.h"
	P_nl_after_last_packet,
};

// These struct are used to deduce the size of the tag lists:
#define PACKET(name, number ,fields) struct name ## _tag_len_struct { fields };
#define INTEGER(pn,pr,member) int member; int tag_and_len ## member;
#define INT64(pn,pr,member) __u64 member; int tag_and_len ## member;
#define BIT(pn,pr,member)   unsigned char member : 1; int tag_and_len ## member;
#define STRING(pn,pr,member,len) unsigned char member[len]; int member ## _len; \
				 int tag_and_len ## member;
#include "linux/drbd_nl.h"

// declate tag-list-sizes
const int tag_list_sizes[] = {
#define PACKET(name,number,fields) 2 fields ,
#define INTEGER(pn,pr,member)     +4+4 
#define INT64(pn,pr,member)       +4+8
#define BIT(pn,pr,member)         +4+1
#define STRING(pn,pr,member,len)  +4+len
#include "drbd_nl.h"
};

/* The two highest bits are used for the tag type */
#define TT_MASK      0xC000
#define TT_INTEGER   0x0000
#define TT_INT64     0x4000
#define TT_BIT       0x8000
#define TT_STRING    0xC000
/* The next bit indicates if processing of the tag is mandatory */
#define T_MANDATORY  0x2000
#define T_MAY_IGNORE 0x0000
#define TN_MASK      0x1fff
/* The remaining 13 bits are used to enumerate the tags */

#define tag_type(T)   ((T) & TT_MASK)
#define tag_number(T) ((T) & TN_MASK)

// declare tag enums
#define PACKET(name, number, fields) fields
enum drbd_tags {
#define INTEGER(pn,pr,member)    T_ ## member = pn | TT_INTEGER | pr ,
#define INT64(pn,pr,member)      T_ ## member = pn | TT_INT64   | pr ,
#define BIT(pn,pr,member)        T_ ## member = pn | TT_BIT     | pr ,
#define STRING(pn,pr,member,len) T_ ## member = pn | TT_STRING  | pr ,
#include "drbd_nl.h"
};

struct tag {
	const char* name;
	int type_n_flags;
};

// declare tag names
#define PACKET(name, number, fields) fields
const struct tag tag_descriptions[] = {
#define INTEGER(pn,pr,member)    [ pn ] = { #member, TT_INTEGER | pr },
#define INT64(pn,pr,member)      [ pn ] = { #member, TT_INT64   | pr },
#define BIT(pn,pr,member)        [ pn ] = { #member, TT_BIT     | pr },
#define STRING(pn,pr,member,len) [ pn ] = { #member, TT_STRING  | pr },
#include "drbd_nl.h"
};

#endif
