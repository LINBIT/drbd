#ifndef DRBDADM_H
#define DRBDADM_H

struct d_host_info
{
  char* name;
  char* device;
  char* disk;
  char* address;
  char* port;
};

struct d_option
{
  char* name;
  char* value;
  struct d_option* next;
};

struct d_resource
{
  char* name;
  char* protocol;
  char* ind_cmd;
  struct d_host_info* me;
  struct d_host_info* partner;
  struct d_option* net_options;
  struct d_option* disk_options;
  struct d_option* sync_options;
  struct d_resource* next;
};

extern int config_valid;
extern struct d_resource* config;
extern int line;

#endif
