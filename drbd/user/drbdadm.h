#ifndef DRBDADM_H
#define DRBDADM_H

#include "../drbd_config.h"

struct d_globals
{
  int disable_io_hints;
  int minor_count;
};

struct d_host_info
{
  char* name;
  char* device;
  char* disk;
  char* address;
  char* port;
  char* meta_disk;
  char* meta_index;
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
  struct d_option* startup_options;
  struct d_resource* next;
  struct d_resource* prev;
};

extern int adm_attach(struct d_resource* ,char* );
extern int adm_connect(struct d_resource* ,char* );
extern int adm_resize(struct d_resource* ,char* );
extern int adm_syncer(struct d_resource* ,char* );
extern int m_system(int,char** );
extern struct d_option* find_opt(struct d_option*,char*);

extern char* config_file;
extern int config_valid;
extern struct d_resource* config;
extern struct d_globals global_options;
extern int line;

extern int dry_run;
extern char* drbdsetup;

/* ssprintf() places the result of the printf in the current stack
   frame and sets ptr to the resulting string. If the current stack
   frame is destroyed (=function returns), the allocated memory is
   freed automatically */

#define ssprintf(...) \
         ({ int _ss_size = snprintf(0, 0, ##__VA_ARGS__);        \
         char *_ss_ret = __builtin_alloca(_ss_size+1);           \
         snprintf(_ss_ret, _ss_size+1, ##__VA_ARGS__);           \
         _ss_ret; })
#endif
