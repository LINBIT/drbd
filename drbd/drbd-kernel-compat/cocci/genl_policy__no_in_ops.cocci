// Before v5.2 struct genl_ops has neither .policy nor .maxattr; both live in
// struct genl_family, so all commands have to share one top-level policy.
// NLA_POLICY_NESTED is missing as well, so the generated per-command policies
// go away and are replaced by a hand-written one.

// Forward-declare drbd_tla_nl_policy so it is visible in all files
// that may reference it (drbd_nl.c and drbd_nl_gen.c).
@@
@@
 #include <net/genetlink.h>
+extern const struct nla_policy drbd_tla_nl_policy[];

// Remove .policy from genl_ops entries
@@
expression E;
@@
  {
  ...,
- .policy = E,
  ...,
  }

// Remove .maxattr from genl_ops entries. Anchor on .cmd to only match ops
// entries, not the family struct.
@@
expression E1, E2;
@@
  {
  .cmd = E1,
  ...,
- .maxattr = E2,
  ...,
  }

// Remove the generated per-command policies. They use NLA_POLICY_NESTED and
// are unreferenced now. Only the top-level ones are static, the policies for
// the nested attributes are still needed.
@@
identifier pol =~ "^drbd_";
expression E;
@@
-static const struct nla_policy pol[E] = {
-	...,
-};

// Add the shared policy and its .maxattr to drbd_nl_family, and define the
// policy itself.
@@
symbol drbd_nl_family;
attribute name __ro_after_init;
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
  .parallel_ops = true,
+ .policy = drbd_tla_nl_policy,
+ .maxattr = DRBD_NLA_MAX,
  };

// Take the policy and the max attribute of drbd_pre_doit()'s mandatory-bit
// check from the family instead of the per-command ops.
@@
expression ops;
@@
- ops->policy
+ drbd_tla_nl_policy

@@
expression ops;
@@
- ops->maxattr
+ DRBD_NLA_MAX

// Add .policy to handshake_nl_family
@@
symbol handshake_nl_family, handshake_nl_mcgrps;
attribute name __ro_after_init;
@@
  struct genl_family handshake_nl_family __ro_after_init = {
  ...,
  .mcgrps = handshake_nl_mcgrps,
+ .policy = handshake_done_nl_policy,
  .maxattr = HANDSHAKE_A_DONE_REMOTE_AUTH,
  ...,
  };

// Remove unused handshake_accept_nl_policy definition
@@
symbol handshake_accept_nl_policy;
expression E;
@@
-static const struct nla_policy handshake_accept_nl_policy[E] = {
-	...,
-};
