#ifndef DRBDADM_H
#define DRBDADM_H

struct cnode
{
  char* name;
  enum { CVALUE, CNODE } type;
  union {
    char* value;
    struct cnode* subtree;
  } d;
  struct cnode* next;
};

extern struct cnode* global_conf;

#endif
