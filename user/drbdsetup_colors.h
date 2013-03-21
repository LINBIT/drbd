#ifndef DRBDSETUP_COLORS_H
#define DRBDSETUP_COLORS_H

#include <linux/drbd.h>

enum when_color { NEVER_COLOR = -1, AUTO_COLOR = 0, ALWAYS_COLOR = 1 };
extern enum when_color opt_color;

extern const char *stop_color_code(void);
extern const char *role_color_start(enum drbd_role, bool);
extern const char *role_color_stop(enum drbd_role, bool);
extern const char *cstate_color_start(enum drbd_conn_state);
extern const char *cstate_color_stop(enum drbd_conn_state);
extern const char *repl_state_color_start(enum drbd_repl_state);
extern const char *repl_state_color_stop(enum drbd_repl_state);
extern const char *disk_state_color_start(enum drbd_disk_state, bool);
extern const char *disk_state_color_stop(enum drbd_disk_state, bool);

#endif  /* DRBDSETUP_COLORS_H */
