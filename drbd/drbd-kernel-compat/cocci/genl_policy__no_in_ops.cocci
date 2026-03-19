// Remove .policy from genl_ops entries
@@
expression E;
@@
  {
  ...,
- .policy = E,
  ...,
  }

// Add .policy to drbd_nl_family
@@
symbol drbd_nl_family;
attribute name __ro_after_init;
@@
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
