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
  int mentioned; // for the adjust command.
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

extern int adm_attach(struct d_resource* ,char* );
extern int adm_connect(struct d_resource* ,char* );

extern int config_valid;
extern struct d_resource* config;
extern int line;

extern int dry_run;
extern char* drbdsetup;
extern char ss_buffer[255];

#endif
