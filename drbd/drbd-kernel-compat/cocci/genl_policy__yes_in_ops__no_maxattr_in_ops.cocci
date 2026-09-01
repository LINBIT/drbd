// Before v5.2 struct genl_ops has .policy but no .maxattr, and struct
// genl_family has no .policy. These kernels parse attributes with the
// family-level maximum but the per-op policy, so every per-op policy array
// must be sized to the family maximum. Replace the generated per-command
// policies with one hand-written shared policy of the full size. The .maxattr
// side is handled by genl_maxattr__no_in_ops, which is always applied
// together with this patch.

// Forward-declare drbd_tla_nl_policy so it is visible in all files
// that may reference it (drbd_nl.c and drbd_nl_gen.c).
@@
@@
 #include <net/genetlink.h>
+extern const struct nla_policy drbd_tla_nl_policy[];

// Point every command at the shared policy, in drbd_nl_ops only. The
// handshake ops keep their own per-op policies; those are already sized to
// the handshake family maximum.
@@
symbol drbd_nl_ops;
expression E;
@@
  const struct genl_ops drbd_nl_ops[...] = {
  ...,
  {
  ...,
- .policy = E,
+ .policy = drbd_tla_nl_policy,
  ...,
  },
  ...
  };

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

// Define the shared policy.
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
+};
+
  struct genl_family drbd_nl_family __ro_after_init = {
  ...,
  .parallel_ops = true,
  };
