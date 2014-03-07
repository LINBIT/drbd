#ifndef __DRBD_STRINGS_H
#define __DRBD_STRINGS_H

extern const char *drbd_conn_s_names[];
extern const char *drbd_repl_s_names[];
extern const char *drbd_role_s_names[];
extern const char *drbd_disk_s_names[];
extern const char *drbd_state_sw_errors[];

extern const char *drbd_repl_str(enum drbd_repl_state);
extern const char *drbd_conn_str(enum drbd_conn_state);
extern const char *drbd_role_str(enum drbd_role);
extern const char *drbd_disk_str(enum drbd_disk_state);
extern const char *drbd_set_st_err_str(enum drbd_state_rv);

#endif  /* __DRBD_STRINGS_H */
