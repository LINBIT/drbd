// From v5.2 (3b0f31f2b8c9) to v5.9 struct genl_ops has no .policy; it lives in
// struct genl_family, so all commands have to share one top-level policy. The
// generated per-command policies are unreferenced then and are replaced by a
// hand-written shared one. (Kernels before v5.2 have .policy in genl_ops, just
// no .maxattr; they are handled by genl_policy__yes_in_ops__no_maxattr_in_ops
// and genl_maxattr__no_in_ops instead.)

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

// Remove the generated per-command policies; they are unreferenced now. Only
// the top-level ones are static, the policies for the nested attributes are
// still needed.
@@
identifier pol =~ "^drbd_";
expression E;
@@
-static const struct nla_policy pol[E] = {
-	...,
-};

// Add the shared policy to drbd_nl_family, and define the policy itself.
// The family-level .maxattr is added by genl_maxattr__no_in_ops, which is
// always applied together with this patch.
@@
symbol drbd_nl_family, true;
attribute name __ro_after_init;
@@
+const struct nla_policy drbd_tla_nl_policy[__DRBD_NLA_MAX] = {
+	[DRBD_NLA_CFG_REPLY]		= { .type = NLA_NESTED },
+	[DRBD_NLA_CFG_CONTEXT]		= { .type = NLA_NESTED },
+	[DRBD_NLA_DISK_CONF]		= { .type = NLA_NESTED },
+	[DRBD_NLA_RESOURCE_OPTS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_NET_CONF]		= { .type = NLA_NESTED },
+	[DRBD_NLA_SET_ROLE_PARMS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_RESIZE_PARMS]		= { .type = NLA_NESTED },
+	[DRBD_NLA_START_OV_PARMS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_NEW_C_UUID_PARMS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_TIMEOUT_PARMS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_DISCONNECT_PARMS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_DETACH_PARMS]		= { .type = NLA_NESTED },
+	[DRBD_NLA_DEVICE_CONF]		= { .type = NLA_NESTED },
+	[DRBD_NLA_RESOURCE_INFO]	= { .type = NLA_NESTED },
+	[DRBD_NLA_DEVICE_INFO]		= { .type = NLA_NESTED },
+	[DRBD_NLA_CONNECTION_INFO]	= { .type = NLA_NESTED },
+	[DRBD_NLA_PEER_DEVICE_INFO]	= { .type = NLA_NESTED },
+	[DRBD_NLA_RESOURCE_STATISTICS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_DEVICE_STATISTICS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_CONNECTION_STATISTICS]= { .type = NLA_NESTED },
+	[DRBD_NLA_PEER_DEVICE_STATISTICS]= { .type = NLA_NESTED },
+	[DRBD_NLA_NOTIFICATION_HEADER]	= { .type = NLA_NESTED },
+	[DRBD_NLA_HELPER]		= { .type = NLA_NESTED },
+	[DRBD_NLA_INVALIDATE_PARMS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_FORGET_PEER_PARMS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_PEER_DEVICE_OPTS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_PATH_PARMS]		= { .type = NLA_NESTED },
+	[DRBD_NLA_CONNECT_PARMS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_PATH_INFO]		= { .type = NLA_NESTED },
+	[DRBD_NLA_RENAME_RESOURCE_PARMS]= { .type = NLA_NESTED },
+	[DRBD_NLA_RENAME_RESOURCE_INFO]	= { .type = NLA_NESTED },
+	[DRBD_NLA_INVAL_PEER_PARAMS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_SUSPEND_IO_PARAMS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_CBT_START_PARMS]	= { .type = NLA_NESTED },
+	[DRBD_NLA_CBT_INFO]		= { .type = NLA_NESTED },
+};
+
  struct genl_family drbd_nl_family __ro_after_init = {
  ...,
  .parallel_ops = true,
+ .policy = drbd_tla_nl_policy,
  };

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
