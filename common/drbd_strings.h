#ifndef __DRBD_STRINGS_H
#define __DRBD_STRINGS_H

struct state_names {
	const char **names;
	unsigned int size;
};

extern struct state_names drbd_conn_state_names;
extern struct state_names drbd_repl_state_names;
extern struct state_names drbd_role_state_names;
extern struct state_names drbd_disk_state_names;
extern struct state_names drbd_error_messages;

enum drbd_packet;

extern const char *drbd_repl_str(enum drbd_repl_state);
extern const char *drbd_conn_str(enum drbd_conn_state);
extern const char *drbd_role_str(enum drbd_role);
extern const char *drbd_disk_str(enum drbd_disk_state);
extern const char *drbd_set_st_err_str(enum drbd_state_rv);
extern const char *drbd_packet_name(enum drbd_packet);


#endif  /* __DRBD_STRINGS_H */
