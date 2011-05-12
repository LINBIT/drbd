#ifndef __DRBD_CONFIG_FLAGS_H
#define __DRBD_CONFIG_FLAGS_H

struct msg_buff;
struct nlattr;

struct context_def;

struct field_def {
	const char *name;
	unsigned short nla_type;
	bool (*is_default)(struct field_def *, const char *);
	bool (*is_equal)(struct field_def *, const char *, const char *);
	const char *(*get)(struct context_def *, struct field_def *, struct nlattr *);
	bool (*put)(struct context_def *, struct field_def *, struct msg_buff *, const char *);
	int (*usage)(struct field_def *, char *, int);
	void (*describe_xml)(struct field_def *);
	union {
		struct {
			const char **map;
			int size;
			int def;
		} e;  /* ENUM, ENUM_NOCASE */
		struct {
			long long min;
			long long max;
			long long def;
			char scale;
		} n;  /* NUMERIC */
		struct {
			bool def;
		} b;  /* BOOLEAN */
	} u;
	bool needs_double_quoting;
	bool argument_is_optional;
	const char *unit;
};

struct context_def {
	struct nla_policy *nla_policy;
	int nla_policy_size;
	struct field_def fields[];
};

extern struct context_def disk_options_ctx;
extern struct context_def net_options_ctx;
extern struct context_def primary_cmd_ctx;
extern struct context_def attach_cmd_ctx;
extern struct context_def connect_cmd_ctx;
extern struct context_def disconnect_cmd_ctx;
extern struct context_def resize_cmd_ctx;
extern struct context_def resource_options_cmd_ctx;
extern struct context_def new_current_uuid_cmd_ctx;
extern struct context_def verify_cmd_ctx;
extern struct context_def new_minor_cmd_ctx;

extern const char *double_quote_string(const char *str);

#endif  /* __DRBD_CONFIG_FLAGS_H */
