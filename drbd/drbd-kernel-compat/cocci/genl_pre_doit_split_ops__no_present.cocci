// Convert all genl_split_ops to genl_ops (covers type declarations,
// function signatures, extern declarations, and definitions)
@@
@@
-struct genl_split_ops
+struct genl_ops

// Forward-declare drbd_tla_nl_policy so it is visible in all files
// that may reference it (drbd_nl.c and drbd_nl_gen.c).
@@
@@
 #include <net/genetlink.h>
+extern const struct nla_policy drbd_tla_nl_policy[];

// Convert .split_ops/.n_split_ops to .ops/.n_ops in drbd_nl_family,
// add family-level maxattr/pre_doit/post_doit, and insert the unified
// TLA policy definition before the family struct.
@@
symbol drbd_nl_family, true;
attribute name __ro_after_init;
expression E1, E2;
@@
+// .len is the max nested attribute number; used by drbd_check_mandatory()
+// to reject unknown mandatory attributes.
+const struct nla_policy drbd_tla_nl_policy[__DRBD_NLA_MAX] = {
+	[DRBD_NLA_CFG_REPLY]		= { .type = NLA_NESTED, .len = DRBD_A_DRBD_CFG_REPLY_MAX },
+	[DRBD_NLA_CFG_CONTEXT]		= { .type = NLA_NESTED, .len = DRBD_A_DRBD_CFG_CONTEXT_MAX },
+	[DRBD_NLA_DISK_CONF]		= { .type = NLA_NESTED, .len = DRBD_A_DISK_CONF_MAX },
+	[DRBD_NLA_RESOURCE_OPTS]	= { .type = NLA_NESTED, .len = DRBD_A_RES_OPTS_MAX },
+	[DRBD_NLA_NET_CONF]		= { .type = NLA_NESTED, .len = DRBD_A_NET_CONF_MAX },
+	[DRBD_NLA_SET_ROLE_PARMS]	= { .type = NLA_NESTED, .len = DRBD_A_SET_ROLE_PARMS_MAX },
+	[DRBD_NLA_RESIZE_PARMS]		= { .type = NLA_NESTED, .len = DRBD_A_RESIZE_PARMS_MAX },
+	[DRBD_NLA_START_OV_PARMS]	= { .type = NLA_NESTED, .len = DRBD_A_START_OV_PARMS_MAX },
+	[DRBD_NLA_NEW_C_UUID_PARMS]	= { .type = NLA_NESTED, .len = DRBD_A_NEW_C_UUID_PARMS_MAX },
+	[DRBD_NLA_TIMEOUT_PARMS]	= { .type = NLA_NESTED, .len = DRBD_A_TIMEOUT_PARMS_MAX },
+	[DRBD_NLA_DISCONNECT_PARMS]	= { .type = NLA_NESTED, .len = DRBD_A_DISCONNECT_PARMS_MAX },
+	[DRBD_NLA_DETACH_PARMS]		= { .type = NLA_NESTED, .len = DRBD_A_DETACH_PARMS_MAX },
+	[DRBD_NLA_DEVICE_CONF]		= { .type = NLA_NESTED, .len = DRBD_A_DEVICE_CONF_MAX },
+	[DRBD_NLA_RESOURCE_INFO]	= { .type = NLA_NESTED, .len = DRBD_A_RESOURCE_INFO_MAX },
+	[DRBD_NLA_DEVICE_INFO]		= { .type = NLA_NESTED, .len = DRBD_A_DEVICE_INFO_MAX },
+	[DRBD_NLA_CONNECTION_INFO]	= { .type = NLA_NESTED, .len = DRBD_A_CONNECTION_INFO_MAX },
+	[DRBD_NLA_PEER_DEVICE_INFO]	= { .type = NLA_NESTED, .len = DRBD_A_PEER_DEVICE_INFO_MAX },
+	[DRBD_NLA_RESOURCE_STATISTICS]	= { .type = NLA_NESTED, .len = DRBD_A_RESOURCE_STATISTICS_MAX },
+	[DRBD_NLA_DEVICE_STATISTICS]	= { .type = NLA_NESTED, .len = DRBD_A_DEVICE_STATISTICS_MAX },
+	[DRBD_NLA_CONNECTION_STATISTICS]= { .type = NLA_NESTED, .len = DRBD_A_CONNECTION_STATISTICS_MAX },
+	[DRBD_NLA_PEER_DEVICE_STATISTICS]= { .type = NLA_NESTED, .len = DRBD_A_PEER_DEVICE_STATISTICS_MAX },
+	[DRBD_NLA_NOTIFICATION_HEADER]	= { .type = NLA_NESTED, .len = DRBD_A_DRBD_NOTIFICATION_HEADER_MAX },
+	[DRBD_NLA_HELPER]		= { .type = NLA_NESTED, .len = DRBD_A_DRBD_HELPER_INFO_MAX },
+	[DRBD_NLA_INVALIDATE_PARMS]	= { .type = NLA_NESTED, .len = DRBD_A_INVALIDATE_PARMS_MAX },
+	[DRBD_NLA_FORGET_PEER_PARMS]	= { .type = NLA_NESTED, .len = DRBD_A_FORGET_PEER_PARMS_MAX },
+	[DRBD_NLA_PEER_DEVICE_OPTS]	= { .type = NLA_NESTED, .len = DRBD_A_PEER_DEVICE_CONF_MAX },
+	[DRBD_NLA_PATH_PARMS]		= { .type = NLA_NESTED, .len = DRBD_A_PATH_PARMS_MAX },
+	[DRBD_NLA_CONNECT_PARMS]	= { .type = NLA_NESTED, .len = DRBD_A_CONNECT_PARMS_MAX },
+	[DRBD_NLA_PATH_INFO]		= { .type = NLA_NESTED, .len = DRBD_A_DRBD_PATH_INFO_MAX },
+	[DRBD_NLA_RENAME_RESOURCE_PARMS]= { .type = NLA_NESTED, .len = DRBD_A_RENAME_RESOURCE_PARMS_MAX },
+	[DRBD_NLA_RENAME_RESOURCE_INFO]	= { .type = NLA_NESTED, .len = DRBD_A_RENAME_RESOURCE_INFO_MAX },
+	[DRBD_NLA_INVAL_PEER_PARAMS]	= { .type = NLA_NESTED, .len = DRBD_A_INVALIDATE_PEER_PARMS_MAX },
+	[DRBD_NLA_SUSPEND_IO_PARAMS]	= { .type = NLA_NESTED, .len = DRBD_A_SUSPEND_IO_PARMS_MAX },
+};
+
 struct genl_family drbd_nl_family __ro_after_init = {
     ...,
-    .split_ops	= E1,
-    .n_split_ops	= E2,
+    .ops	= E1,
+    .n_ops	= E2,
     ...,
+    .maxattr	= DRBD_NLA_MAX,
+    .pre_doit	= drbd_pre_doit,
+    .post_doit	= drbd_post_doit,
 };

// Remove per-op pre_doit/post_doit/maxattr (not valid in genl_ops).
// Anchor on .cmd to only match ops entries, not the family struct.
@@
expression E1, E2;
@@
 {
     .cmd = E1,
     ...,
-    .pre_doit = E2,
     ...,
 }

@@
expression E1, E2;
@@
 {
     .cmd = E1,
     ...,
-    .post_doit = E2,
     ...,
 }

@@
expression E1, E2;
@@
 {
     .cmd = E1,
     ...,
-    .maxattr = E2,
     ...,
 }

// Remove unused static per-op policy arrays (they reference
// NLA_POLICY_NESTED which may not exist on old kernels).
// Only match arrays in the drbd_nl_ops file (drbd_nl_gen.c),
// not handshake policy arrays which are still needed.
@@
identifier pol =~ "^drbd_";
expression E;
@@
-static const struct nla_policy pol[E] = {
-	...,
-};

// Replace per-op policy with unified tla policy in drbd_nl_ops only
// (don't touch handshake_nl_ops which has its own per-op policies)
@@
symbol drbd_nl_ops;
expression E;
@@
 const struct genl_ops drbd_nl_ops[...] = {
     ...,
     {
         ...,
-        .policy = E,
+        .policy = drbd_tla_nl_policy,
         ...,
     },
     ...
 };

// Replace ops->policy access with the unified policy
@@
expression ops;
@@
- ops->policy
+ drbd_tla_nl_policy

// Replace ops->maxattr access
@@
expression ops;
@@
- ops->maxattr
+ DRBD_NLA_MAX

// Remove GENL_CMD_CAP_DO from flags
@@
expression E;
@@
- E | GENL_CMD_CAP_DO
+ E

// Remove GENL_CMD_CAP_DUMP from flags
@@
expression E;
@@
- E | GENL_CMD_CAP_DUMP
+ E
