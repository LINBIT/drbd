#ifndef DRBDADM_H
#define DRBDADM_H

#include <linux/drbd_config.h>
#include <sys/utsname.h>
#include <sys/types.h>

#define E_syntax	  2
#define E_usage		  3
#define E_config_invalid 10
#define E_exec_error     20
#define E_thinko	 42 /* :) */

#define SF_MaySleep       2
#define SF_ReturnPid      4

/* for check_uniq(): Check for uniqueness of certain values...
 * comment out if you want to NOT choke on the first conflict */
#define EXIT_ON_CONFLICT

/* for verify_ips(): make not verifyable ips fatal */
//#define INVALID_IP_IS_INVALID_CONF

struct d_globals
{
  int disable_io_hints;
  int minor_count;
  int dialog_refresh;
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
  struct d_host_info* peer;
  struct d_option* net_options;
  struct d_option* disk_options;
  struct d_option* sync_options;
  struct d_option* startup_options;
  struct d_resource* next;
};

extern int adm_attach(struct d_resource* ,char* );
extern int adm_connect(struct d_resource* ,char* );
extern int adm_resize(struct d_resource* ,char* );
extern int adm_syncer(struct d_resource* ,char* );
extern int m_system(int,char** );
extern struct d_option* find_opt(struct d_option*,char*);
extern void validate_resource(struct d_resource *);
extern int check_uniq(const char* what, const char *fmt, ...);
extern void verify_ips(struct d_resource* res);


extern char* config_file;
extern int config_valid;
extern struct d_resource* config;
extern struct d_globals global_options;
extern int line, fline, c_resource_start;

extern int dry_run;
extern char* drbdsetup;
extern char ss_buffer[255];
extern struct utsname nodeinfo;


/* ssprintf() places the result of the printf in the current stack
   frame and sets ptr to the resulting string. If the current stack
   frame is destroyed (=function returns), the allocated memory is
   freed automatically */

/*
  // This is the nicer version, that does not need the ss_buffer. 
  // But it only works with very new glibcs.
   
#define ssprintf(...) \
         ({ int _ss_size = snprintf(0, 0, ##__VA_ARGS__);        \
         char *_ss_ret = __builtin_alloca(_ss_size+1);           \
         snprintf(_ss_ret, _ss_size+1, ##__VA_ARGS__);           \
         _ss_ret; })
*/

#define ssprintf(ptr,...) \
  ptr=strcpy(alloca(snprintf(ss_buffer,255,##__VA_ARGS__)+1),ss_buffer)

/* CAUTION: arguments may not have side effects! */
#define for_each_resource(res,tmp,config) \
	for (res = (config); res && (tmp = res->next, 1); res = tmp)

#endif
