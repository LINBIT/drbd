#ifndef DRBDADM_H
#define DRBDADM_H

#include <linux/drbd_config.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <net/if.h>
#include <stdint.h>
#include <stdarg.h>

#include "config.h"

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

  SUPRESS_STDERR       = 0x10,
  RETURN_STDOUT_FD     = 0x20,
  RETURN_STDERR_FD     = 0x40,
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

struct d_name
{
  char *name;
  struct d_name *next;
};

struct d_proxy_info
{
  struct d_name *on_hosts;
  char* inside_addr;
  char* inside_port;
  char* inside_af;
  char* outside_addr;
  char* outside_port;
  char* outside_af;
};

struct d_volume
{
  unsigned vnr;
  char* device;
  unsigned device_minor;
  char* disk;
  char* meta_disk;
  char* meta_index;
  int meta_major;
  int meta_minor;
  struct d_volume *next;
  unsigned int implicit :1 ; /* Do not dump an explicit volume section */
};

struct d_host_info
{
  struct d_name *on_hosts;
  struct d_volume *volumes;
  char* address;
  char* port;
  char* address_family;
  struct d_proxy_info *proxy;
  struct d_host_info* next;
  struct d_resource* lower;  /* for device stacking */
  char *lower_name;          /* for device stacking, before bind_stacked_res() */
  int config_line;
  unsigned int by_address:1; /* Match to machines by address, not by names (=on_hosts) */
};

struct d_option
{
  char* name;
  char* value;
  struct d_option* next;
  unsigned int mentioned  :1 ; // for the adjust command.
  unsigned int is_default :1 ; // for the adjust command.
  unsigned int is_escaped :1 ;
};

struct d_resource
{
  char* name;
  char* protocol;

  struct d_volume *volumes;   /* gets propagated to host_info sections later. */

  struct d_host_info* me;
  struct d_host_info* peer;
  struct d_host_info* all_hosts;
  struct d_option* net_options;
  struct d_option* disk_options;
  struct d_option* res_options;
  struct d_option* startup_options;
  struct d_option* handlers;
  struct d_option* proxy_options;
  struct d_option* proxy_plugins;
  struct d_resource* next;
  struct d_name *become_primary_on;
  char *config_file; /* The config file this resource is define in.*/
  int start_line;
  unsigned int stacked_timeouts:1;
  unsigned int ignore:1;
  unsigned int stacked:1;        /* Stacked on this node */
  unsigned int stacked_on_one:1; /* Stacked either on me or on peer */
};

struct adm_cmd;

struct cfg_ctx {
	/* res == NULL: does not care for resources, or iterates over all
	 * resources in the global "struct d_resource *config" */
	struct d_resource *res;
	/* vol == NULL: operate on the resource itself, or iterates over all
	 * volumes in res */
	struct d_volume *vol;

	const char *arg;
};


extern char *canonify_path(char *path);
extern int adm_create_md(struct cfg_ctx *);
extern int adm_attach(struct cfg_ctx *);
extern int adm_connect(struct cfg_ctx *);
extern int adm_resize(struct cfg_ctx *);
extern int adm_syncer(struct cfg_ctx *);
extern int adm_generic_s(struct cfg_ctx *);
extern int _admm_generic(struct cfg_ctx *, int flags);
extern void m__system(char **argv, int flags, const char *res_name, pid_t *kid, int *fd, int *ex);
static inline int m_system_ex(char **argv, int flags, const char *res_name)
{
	int ex;
	m__system(argv, flags, res_name, NULL, NULL, &ex);
	return ex;
}
extern struct d_option* find_opt(struct d_option*,char*);
extern void validate_resource(struct d_resource *);
/* stages of configuration, as performed on "drbdadm up"
 * or "drbdadm adjust":
 */
enum drbd_cfg_stage {
	/* prerequisite stage: create objects, start daemons, ... */
	CFG_PREREQ,

	/* detach/attach local disks, */
	CFG_DISK,

	/* The stage to discard network configuration, during adjust.
	 * This is after the DISK stage, because we don't want to cut access to
	 * good data while in primary role.  And before the SETTINGS stage, as
	 * some proxy or syncer settings may cause side effects and additional
	 * handshakes while we have an established connection.
	 */
	CFG_NET_PREREQ,

	/* (re)set syncer parameters, */
	CFG_SETTINGS,

	/* discard/set connection parameters */
	CFG_NET,

	__CFG_LAST
};

extern void schedule_dcmd( int (*function)(struct cfg_ctx *),
			   struct d_resource *res,
			   struct d_volume *vol,
			   const char *arg,
			   enum drbd_cfg_stage stage);

extern int version_code_kernel(void);
extern int version_code_userland(void);
extern void warn_on_version_mismatch(void);
extern void uc_node(enum usage_count_type type);
extern void convert_discard_opt(struct d_resource* res);
extern void convert_after_option(struct d_resource* res);
extern int have_ip(const char *af, const char *ip);

/* See drbdadm_minor_table.c */
extern int register_minor(int minor, const char *path);
extern int unregister_minor(int minor);
extern char *lookup_minor(int minor);

enum pr_flags {
  NoneHAllowed  = 4,
  IgnDiscardMyData = 8
};
enum pp_flags {
	match_on_proxy = 1,
};
extern struct d_resource* parse_resource(char*, enum pr_flags);
extern void post_parse(struct d_resource *config, enum pp_flags);
extern struct d_option *new_opt(char *name, char *value);
extern int name_in_names(char *name, struct d_name *names);
extern char *_names_to_str(char* buffer, struct d_name *names);
extern char *_names_to_str_c(char* buffer, struct d_name *names, char c);
#define NAMES_STR_SIZE 255
#define names_to_str(N) _names_to_str(alloca(NAMES_STR_SIZE+1), N)
#define names_to_str_c(N, C) _names_to_str_c(alloca(NAMES_STR_SIZE+1), N, C)
extern void free_names(struct d_name *names);
extern void set_me_in_resource(struct d_resource* res, int match_on_proxy);
extern void set_peer_in_resource(struct d_resource* res, int peer_required);
extern void set_on_hosts_in_res(struct d_resource *res);
extern void set_disk_in_res(struct d_resource *res);
extern char *proxy_connection_name(struct d_resource *res);
int parse_proxy_settings(struct d_resource *res, int check_proxy_token);
/* conn_name is optional and mostly for compatibility with dcmd */
int do_proxy_conn_up(struct cfg_ctx *ctx);
int do_proxy_conn_down(struct cfg_ctx *ctx);
int do_proxy_conn_plugins(struct cfg_ctx *ctx);

extern char *config_file;
extern char *config_save;
extern int config_valid;
extern struct d_resource* config;
extern struct d_resource* common;
extern struct d_globals global_options;
extern int line, fline;
extern struct hsearch_data global_htable;

extern int no_tty;
extern int dry_run;
extern int verbose;
extern char* drbdsetup;
extern char* drbd_proxy_ctl;
extern char ss_buffer[1024];
extern struct utsname nodeinfo;

extern char* setup_opts[10];
extern char* connect_to_host;
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
  ptr=strcpy(alloca(snprintf(ss_buffer,sizeof(ss_buffer),##__VA_ARGS__)+1),ss_buffer)

/* CAUTION: arguments may not have side effects! */
#define for_each_resource(res,tmp,config) \
	for (res = (config); res && (tmp = res->next, 1); res = tmp)

#define for_each_volume(v_,volumes_) \
	for (v_ = volumes_; v_; v_ = v_->next)

#define APPEND(LIST,ITEM) ({		      \
  typeof((LIST)) _l = (LIST);		      \
  typeof((ITEM)) _i = (ITEM);		      \
  typeof((ITEM)) _t;			      \
  _i->next = NULL;			      \
  if (_l == NULL) { _l = _i; }		      \
  else {				      \
    for (_t = _l; _t->next; _t = _t->next);   \
    _t->next = _i;			      \
  };					      \
  _l;					      \
})

#define SPLICE(LIST,ITEMS) ({		      \
  typeof((LIST)) _l = (LIST);		      \
  typeof((ITEMS)) _i = (ITEMS);		      \
  typeof((ITEMS)) _t;			      \
  if (_l == NULL) { _l = _i; }		      \
  else {				      \
    for (_t = _l; _t->next; _t = _t->next);   \
    _t->next = _i;			      \
  };					      \
  _l;					      \
})


#define PARSER_CHECK_PROXY_KEYWORD (1)
#define PARSER_STOP_IF_INVALID (2)

#endif

