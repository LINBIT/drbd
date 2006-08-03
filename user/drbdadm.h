#ifndef DRBDADM_H
#define DRBDADM_H

#include <linux/drbd_config.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <net/if.h>
#include <stdint.h>

#define E_syntax	  2
#define E_usage		  3
#define E_config_invalid 10
#define E_exec_error     20
#define E_thinko	 42 /* :) */

enum {
  SLEEPS_FINITE        = 1,
  SLEEPS_SHORT         = 2+1,
  SLEEPS_LONG          = 4+1,
  SLEEPS_VERY_LONG     = 8+1,
  SLEEPS_MASK          = 15,

  RETURN_PID           = 2,
  SLEEPS_FOREVER       = 4,

  SUPRESS_STDERR       = 16,

  DONT_REPORT_FAILED   = 0x80,
};

/* for check_uniq(): Check for uniqueness of certain values...
 * comment out if you want to NOT choke on the first conflict */
#define EXIT_ON_CONFLICT 1

/* for verify_ips(): are not verifyable ips fatal? */
#define INVALID_IP_IS_INVALID_CONF 1

enum usage_count_type {
  UC_YES,
  UC_NO,
  UC_ASK,
};
  
struct d_globals
{
  int disable_io_hints;
  int disable_ip_verification;
  int minor_count;
  int dialog_refresh;
  enum usage_count_type usage_count;
};

#define IFI_HADDR 8
#define IFI_ALIAS 1

struct ifi_info {
  char ifi_name[IFNAMSIZ];      /* interface name, nul terminated */
  uint8_t ifi_haddr[IFI_HADDR]; /* hardware address */
  uint16_t ifi_hlen;            /* bytes in hardware address, 0, 6, 8 */
  short ifi_flags;              /* IFF_xxx constants from <net/if.h> */
  short ifi_myflags;            /* our own IFI_xxx flags */
  struct sockaddr *ifi_addr;    /* primary address */
  struct ifi_info *ifi_next;    /* next ifi_info structure */
};

struct d_host_info
{
  char* name;
  char* device;
  char* disk;
  int disk_major;
  int disk_minor;
  char* address;
  char* port;
  char* meta_disk;
  int meta_major;
  int meta_minor;
  char* meta_index;
};

struct d_option
{
  char* name;
  char* value;
  struct d_option* next;
  unsigned int mentioned  :1 ; // for the adjust command.
  unsigned int is_default :1 ; // for the adjust command.
};

struct d_resource
{
  char* name;
  char* protocol;
  struct d_host_info* me;
  struct d_host_info* peer;
  struct d_option* net_options;
  struct d_option* disk_options;
  struct d_option* sync_options;
  struct d_option* startup_options;
  struct d_option* handlers;
  struct d_resource* next;
};

extern int adm_attach(struct d_resource* ,const char* );
extern int adm_connect(struct d_resource* ,const char* );
extern int adm_resize(struct d_resource* ,const char* );
extern int adm_syncer(struct d_resource* ,const char* );
extern int _admm_generic(struct d_resource* ,const char*, int flags);
extern int m_system(char**,int );
extern struct d_option* find_opt(struct d_option*,char*);
extern void validate_resource(struct d_resource *);
extern int check_uniq(const char* what, const char *fmt, ...);
extern void verify_ips(struct d_resource* res);
extern void schedule_dcmd( int (* function)(struct d_resource*,const char* ),
			   struct d_resource* res,
			   int order);

extern void uc_node(enum usage_count_type type);
extern int adm_create_md(struct d_resource* res ,const char* cmd);
extern void convert_discard_opt(struct d_resource* res);
extern void convert_after_option(struct d_resource* res);

extern char* config_file;
extern int config_valid;
extern struct d_resource* config;
extern struct d_resource* common;
extern struct d_globals global_options;
extern int line, fline, c_resource_start;

extern int no_tty;
extern int dry_run;
extern char* drbdsetup;
extern char ss_buffer[255];
extern struct utsname nodeinfo;

extern char* setup_opts[10];
extern int soi;


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
