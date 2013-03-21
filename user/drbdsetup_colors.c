#include <stdbool.h>
#include "drbdtool_common.h"
#include "drbdsetup_colors.h"

enum when_color opt_color;

enum colors {
	COLOR_TRANSITIONAL,  /* default */
	COLOR_NORMAL,
	COLOR_PRIMARY,
	COLOR_GOOD,
	COLOR_BAD,
};

#define LC "\033["
#define RC "m"

const char *local_color_codes[] = {
	[COLOR_TRANSITIONAL]	= LC "1" RC,		/* bold */
	[COLOR_NORMAL]		= NULL,
	[COLOR_PRIMARY]		= LC "1;36" RC,		/* cyan */
	[COLOR_GOOD]		= LC "1;32" RC,		/* green */
	[COLOR_BAD]		= LC "1;31" RC,		/* red */
};

const char *peer_color_codes[] = {
	[COLOR_TRANSITIONAL]	= NULL,
	[COLOR_NORMAL]		= NULL,
	[COLOR_PRIMARY]		= LC "36" RC,		/* cyan */
	[COLOR_GOOD]		= LC "32" RC,		/* green */
	[COLOR_BAD]		= LC "31" RC,		/* red */
};

int role_colors[] = {
	[R_PRIMARY] = COLOR_PRIMARY,
	[R_SECONDARY] = COLOR_NORMAL,
	[R_UNKNOWN] = COLOR_TRANSITIONAL,
};

int cstate_colors[] = {
	[C_STANDALONE] = COLOR_BAD,
	[C_CONNECTING] = COLOR_BAD,
	[C_CONNECTED] = COLOR_NORMAL,
};

int repl_state_colors[] = {
	[L_OFF] = COLOR_TRANSITIONAL,
	[L_ESTABLISHED] = COLOR_NORMAL,
	[L_SYNC_SOURCE] = COLOR_BAD,
	[L_SYNC_TARGET] = COLOR_BAD,
	[L_VERIFY_S] = COLOR_NORMAL,
	[L_VERIFY_T] = COLOR_NORMAL,
	[L_PAUSED_SYNC_S] = COLOR_NORMAL,
	[L_PAUSED_SYNC_T] = COLOR_BAD,
	[L_AHEAD] = COLOR_NORMAL,
	[L_BEHIND] = COLOR_TRANSITIONAL,
};

int disk_state_colors[] = {
	[D_DISKLESS] = COLOR_BAD,
	[D_INCONSISTENT] = COLOR_BAD,
	[D_OUTDATED] = COLOR_BAD,
	[D_CONSISTENT] = COLOR_TRANSITIONAL,
	[D_UP_TO_DATE] = COLOR_GOOD,
};

const char *stop_color_code(void)
{
	return LC "0" RC;
}

static const char *color_code(int index, int *array, int size,
			      bool start, bool local)
{
	const char **color_codes = local ?
		local_color_codes : peer_color_codes;
	int i;

	if (opt_color == AUTO_COLOR)
		opt_color = isatty(fileno(stdout)) ? ALWAYS_COLOR : NEVER_COLOR;
	if (opt_color == NEVER_COLOR)
		return "";

	if (index < size)
		i = array[index];
	else
		i = COLOR_TRANSITIONAL;
	if (color_codes[i])
		return start ? color_codes[i] : stop_color_code();
	else
		return "";
}

const char *role_color_start(enum drbd_role role, bool local)
{
	return color_code(role, role_colors,
			  ARRAY_SIZE(role_colors), true, local);
}

const char *role_color_stop(enum drbd_role role, bool local)
{
	return color_code(role, role_colors,
			  ARRAY_SIZE(role_colors), false, local);
}

const char *cstate_color_start(enum drbd_conn_state cstate)
{
	return color_code(cstate, cstate_colors,
			 ARRAY_SIZE(cstate_colors), true, true);
}

const char *cstate_color_stop(enum drbd_conn_state cstate)
{
	return color_code(cstate, cstate_colors,
			  ARRAY_SIZE(cstate_colors), false, true);
}

static bool
is_local_repl_state(enum drbd_repl_state repl_state)
{
	switch(repl_state) {
		case L_SYNC_TARGET:
		case L_PAUSED_SYNC_T:
		case L_BEHIND:
			return true;
		default:
			return false;
	}
}

const char *repl_state_color_start(enum drbd_repl_state repl_state)
{
	return color_code(repl_state, repl_state_colors,
			  ARRAY_SIZE(repl_state_colors), true,
			  is_local_repl_state(repl_state));
}

const char *repl_state_color_stop(enum drbd_repl_state repl_state)
{
	return color_code(repl_state, repl_state_colors,
			  ARRAY_SIZE(repl_state_colors), false,
			  is_local_repl_state(repl_state));
}

const char *disk_state_color_start(enum drbd_disk_state disk_state, bool local)
{
	return color_code(disk_state, disk_state_colors,
			  ARRAY_SIZE(disk_state_colors), true, local);
}

const char *disk_state_color_stop(enum drbd_disk_state disk_state, bool local)
{
	return color_code(disk_state, disk_state_colors,
			  ARRAY_SIZE(disk_state_colors), false, local);
}
