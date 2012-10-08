#ifndef DRBDADM_DUMP_H
#define DRBDADM_DUMP_H

#include "drbdadm.h"

extern char *esc(char *str);

extern void print_dump_xml_header(void);
extern void print_dump_header(void);
extern int adm_dump(struct cfg_ctx *ctx);
extern int adm_dump_xml(struct cfg_ctx *ctx);

#endif
