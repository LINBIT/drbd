#ifndef TAG_MAGIC_H
#define TAG_MAGIC_H

#define TT_END     0

// create packet_type enums
enum packet_types {
#define PACKET(name, fields) P_ ## name,
#define INTEGER(pn,member)
#define STRING(pn,member,len)
#include "tag-test.h"
};

// declate structs
#define PACKET(name, fields) struct name { fields };
#define INTEGER(pn,member) int member;
#define STRING(pn,member,len) unsigned char member[len];
#include "tag-test.h"

// declate tag-list-sizes
#define PACKET(name, fields) const name ## _tag_size = 1 fields ;
#define INTEGER(pn,member) +6 
#define STRING(pn, member,len) +2+len
#include "tag-test.h"

// convert to tag list fuctions
#define PACKET(name, fields) \
name ## _to_tags ( struct name * arg, unsigned char* tl) \
{ \
	int i=0; \
	\
	fields \
	tl[i] = TT_END; \
}
#define INTEGER(pn,member) \
	tl[i++] = pn; \
	tl[i++] = sizeof(int); \
	*(int*)(tl+i) = arg->member; \
	i+=sizeof(int);
#define STRING(pn,member,len) \
	tl[i++] = pn; \
	tl[i++] = len; \
	strcpy(tl+i,arg->member); i+=len;
#include "tag-test.h"

// convert from tag list functions
#define PACKET(name, fields) \
name ## _from_tags ( unsigned char* tl, struct name * arg) \
{ \
	int i=0; \
	\
	while( tl[i] != TT_END ) { \
		switch( tl[i++] ) { \
		fields \
		default: i += tl[i++]; /* ignoring unknown */ \
		} \
	} \
}
#define INTEGER(pn,member) \
	case pn: i++; \
		 arg->member = *(int*)(tl+i); \
		 i+=sizeof(int); \
		 break;
#define STRING(pn,member,len) \
	case pn: i++; \
		 strcpy(tl+i,arg->member); \
		 tl+=len; \
		 break; 
#include "tag-test.h"


// dump packet functions
#define PACKET(name, fields) \
dump_ ## name ( const char* n, struct name * arg) \
{ \
	fields \
}
#define INTEGER(pn,member) printf( "%s.%s = %d\n",n,#member,arg->member);
#define STRING(pn,member,len) printf( "%s.%s = %s\n",n,#member,arg->member);
#include "tag-test.h"


void dump_tag_list( const char* n, unsigned char* tl)
{
	int len;

	printf("Tag list %s:\n",n);

	while(*tl != TT_END) {
		printf("tag: %u\n",(int)*tl++);
		len = *tl++;
		printf("len: %u\n",len);
		tl+=len;
	}
}
#endif
